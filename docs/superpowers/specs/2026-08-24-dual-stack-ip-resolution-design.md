# Dual-stack IP resolution via an `ip_resolution` config block — design

**Date:** 2026-08-24
**Status:** Approved (design)
**Author:** Alec Pinson

## Summary

Let a single user have **both** an IPv4 and an IPv6 address whitelisted at the
same time, instead of only whichever family their browser happened to connect
over.

Two independent changes make that possible:

1. **Capture** — a new top-level `ip_resolution` block describes, per address
   family, how to learn the user's address: from a trusted proxy header / the
   connection itself, and/or from a browser-side fetch to a family-pinned echo
   service such as `ipv4.icanhazip.com`.
2. **Storage** — Redis DB0 gains a family suffix so an IPv6 entry no longer
   overwrites the same user's IPv4 entry.

```yaml
ip_resolution:
  ipv4:
    enabled: true
    header: Cf-Connecting-Ip
    url: https://ipv4.icanhazip.com
    url_timeout: 5s
  ipv6:
    enabled: true
    header: Cf-Connecting-Ip
    url: https://ipv6.icanhazip.com
    url_timeout: 5s
```

`ip_resolution` governs **what we collect**. The existing per-resource
`ip_version` field (PR #8) governs **where we send it**. They are orthogonal and
neither replaces the other.

## Motivation

`user.finishUser()` learns exactly one address: whatever arrives on the trusted
header, falling back to `RemoteAddr`. That is a property of the connection, so a
dual-stack user gets whichever family their browser preferred — in practice
IPv6, since browsers prefer it under Happy Eyeballs.

PR #8 made every resource family-aware, so an `ip_version: ipv4` resource
correctly ignores an IPv6 user. The gap it deliberately left open is that such a
user has **no** IPv4 address on record to whitelist. Plenty of services accept
IPv4 only (Azure Key Vault firewall rules are documented as IPv4-only), so a
dual-stack user ends up whitelisted nowhere on those resources.

Closing that requires a second connection over the other family, because the
information simply is not present in the first request.

## Decisions

Settled during brainstorming. Each is recorded because it rules out an
alternative that looks reasonable in isolation.

1. **`url` is fetched by the browser, never by the server.** If the app fetched
   `ipv4.icanhazip.com` it would learn its own egress address, not the user's.
   The page therefore fetches and POSTs the result back.

2. **Addresses arriving via `url` are trusted.** This is a real trust inversion:
   today's address is *observed* by the app and unforgeable, whereas a posted
   address is a *claim* an authenticated user could fabricate (`{"ipv4":
   "8.8.8.8"}` via devtools or curl), whitelisting an address they do not
   control.

   An earlier draft gated this behind a `trust_client: true` flag. That was
   dropped: the flag would be mandatory-`true` for anyone using `url` at all, so
   it carried no information. **Setting `url` is itself the opt-in.** The
   implication is documented at `url` in the README, and a startup log line
   records which families use client-asserted resolution.

3. **No self-hosted echo endpoint, no nonce.** An alternative had `url` point at
   the app itself behind v4-only/v6-only DNS names, making the address observed
   rather than claimed. Rejected: it costs two DNS records plus TLS coverage per
   deployment, and if those hostnames sit behind Cloudflare Access the probe
   fetch gets redirected to a login page and fails CORS — which would have
   needed an unauthenticated nonce-based endpoint to work around. Out of scope.
   `url` may still point at such an endpoint; it is simply still treated as
   client-asserted.

4. **Both families default to `enabled: true`.** An earlier sketch defaulted
   `ipv6` to `false`. That would be a silent regression: today an IPv6-connecting
   user *is* recorded, and `azure/frontdoor` (which defaults to `ip_version:
   both`) whitelists them. Defaulting IPv6 off would stop that on upgrade — the
   same class of bug PR #8 avoided by giving Front Door a `both` default.

5. **`Enabled` is a `*bool`, not a `bool`.** Go's zero value for `bool` is
   `false`, which would make "omitted" indistinguishable from "explicitly
   disabled" and silently disable both families for every existing config.

6. **Resolution order is header → connection → url.** The trusted source always
   wins, and the fetch runs only for a family the connection did not already
   supply. A v6-connected user therefore probes only for v4, and no third-party
   request is made for a family already known.

7. **`auth.ip_header` is deprecated, not removed.** It is documented at
   README:118–134, so it keeps working as the fallback header for any family
   that specifies none, emitting a deprecation warning. Chosen over a hard break.

8. **Family-suffixed Redis keys, not a multi-valued record.** See *Storage*.

9. **`url_timeout` is a flat sibling of `url`, not a nested `custom_probe`
   block.** A nested block would put the value three levels deep
   (`ip_resolution.ipv4.custom_probe.url`) to group exactly two fields, and
   would nest one of the two peer strategies (`url`) while leaving the other
   (`header`) flat, hiding their symmetry. The `url_` prefix carries the
   coupling, and validation covers the rest. If probe options ever multiply,
   promoting them into a block is mechanical.

10. **`url_timeout` is per family, not one shared value.** A single
    `ip_resolution.timeout` would be fewer knobs, and since probes run in
    parallel and failures never block the page there is little practical reason
    to differ — but per-family costs nothing and keeps the two blocks uniform.

## Capture

### Config schema

```go
type IpResolution struct {
    IPv4 IpFamilyResolution `yaml:"ipv4"`
    IPv6 IpFamilyResolution `yaml:"ipv6"`
}

type IpFamilyResolution struct {
    Enabled    *bool  `yaml:"enabled"` // pointer: unset (=> true) must differ from false
    Header     string `yaml:"header"`
    Url        string `yaml:"url"`
    UrlTimeout string `yaml:"url_timeout"` // duration string; resolved to time.Duration at load
}
```

`UrlTimeout` is a `string` run through `time.ParseDuration`, not a
`time.Duration` field: **yaml.v2 will not parse `5s` into a `Duration`** — it
only maps integers, and reads them as nanoseconds. Parsing at load with a fatal
on unparseable input matches the existing `mustResolveIpVersion` convention.
Defaults to `5s` when unset.

Validation in `config.load()`, matching the existing fatal-on-unsupported-value
style:

- both families disabled → fatal (nothing could ever be whitelisted)
- `url` set on a disabled family → fatal (contradictory)
- `url_timeout` set without `url` → fatal (contradictory)
- `url_timeout` not parseable by `time.ParseDuration`, or ≤ 0 → fatal
- `auth.ip_header` still set → deprecation warning

Omitting the `ip_resolution` block entirely must reproduce today's behaviour
byte for byte: both families enabled, header falling back to `auth.ip_header`
then `X-Azure-Clientip` then `RemoteAddr`, and no fetches.

### Request flow

The existing server-side path is unchanged:

1. Request lands (`/callback` for `auth.type: azure`, `/` for `none`).
2. `finishUser` resolves the observed address from header → `RemoteAddr`.
3. Its family is determined; if that family is enabled, it is whitelisted.
4. The page renders.

Layered on top:

5. The template emits probe JS only for families that have a `url` **and** were
   not already satisfied at step 2.
6. The JS fetches each `url` with that family's `url_timeout` (default `5s`)
   and `referrerPolicy: 'no-referrer'`. The resolved timeout is rendered into
   the page, so the browser enforces it via `AbortSignal.timeout()`.
7. On success it POSTs `{"family":"ipv6","ip":"2a00:...:1"}` to a new `/resolve`
   endpoint.
8. `/resolve` re-derives the user exactly as the index handler does — session
   for `azure`, identity header for `none` — then validates the claim. Then it
   whitelists it.
9. The page text updates to show what was whitelisted.

`/resolve` accepts a claim only when **all** of these hold:

- the caller is authenticated (session token for `azure`, identity header for
  `none`); otherwise `401`
- the claimed family is enabled **and has a `url` configured**. Without the
  second condition `/resolve` would accept claims on deployments that never
  opted into client-asserted resolution, which would be an open whitelisting
  endpoint. A claim for a family with no `url` is rejected.
- the IP parses, and its actual family matches the claimed one

One further tightening: if the `/resolve` request itself arrives over the
claimed family, the **observed** address wins and the claim is discarded. That
costs nothing, and it stops a posted claim from overwriting an address the app
could see for itself.

A failed or timed-out fetch is ignored, logged only to the browser console. A
user with no IPv6 connectivity will fail the IPv6 probe on every visit; that is
the normal case, not an error, and must never block the page or the address
that *was* resolved.

### CORS

Verified 2026-08-24 — `ipv4.icanhazip.com` returns:

```
access-control-allow-origin: *
access-control-allow-methods: GET
```

A plain cross-origin GET `fetch()` can therefore read the body. Because the
allowed origin is the wildcard, the fetch **must not** set
`credentials: 'include'` — the Fetch spec rejects that pairing. No credentials
are wanted regardless.

### What is disclosed to the echo service

A cross-origin `fetch()` runs in CORS mode and sends `Origin:
https://<your-host>`, so the echo service learns that the hostname exists and
that a given IP visited it. `Origin` cannot be suppressed without losing the
ability to read the response. `referrerPolicy: 'no-referrer'` removes `Referer`.

No authentication material can leak: cookies are scoped by domain so
`CF_Authorization` is never a candidate for a request to `icanhazip.com`;
`fetch()` defaults to `credentials: 'same-origin'` anyway; and Cloudflare's
`Cf-*` headers are injected inbound to the app and never exist on the browser's
outbound request.

## Storage

Redis DB0 gains a family suffix:

| Family | Key            | Note                          |
|--------|----------------|-------------------------------|
| IPv4   | `<userkey>`    | unchanged — no migration      |
| IPv6   | `<userkey>:v6` | new                           |

`u.key` is `[a-z0-9]+` after the regex strip in `finishUser`, so `:` cannot
collide with a generated key.

Two helpers:

- `redisKey(base string, t IpType) string` — appends `:v6` for IPv6
- `baseKey(k string) string` — strips the suffix

`r.getGroups()` applies `baseKey()` internally. **This is why no provider needs
changing**: every provider iterates `w.List`, sees one additional entry, and its
existing `matchesIpVersion` guard from PR #8 already routes that entry to the
right resources. All 13 guard sites and all seven `update()` methods stay as
they are.

Rejected alternatives:

- **One key holding both addresses.** Changes `w.List` from
  `map[string]string` to `map[string][]string`, touching every guard site and
  every provider.
- **A separate Redis DB for IPv6.** `getWhitelist()` would have to merge two
  DBs into one map, and that map still needs distinct keys per family — so it
  collapses back into suffixing anyway, plus a fourth connection.

Each family expires independently, which is desirable: if a user's IPv6
connectivity goes away, that entry ages out on its own while their IPv4 survives.

### Rate limiting

The 120s per-user API throttle (DB2) is keyed on `baseKey`, so one page load
counts as one call across both families.

No special-casing is required. `whitelist.add()`'s changed-branch does not
consult `canCallApi`, so a genuinely new IPv6 address pushes to providers
immediately; only the unchanged-branch — a refresh with the same addresses — is
throttled. That is already the correct behaviour once `add()` is family-aware.

## Files touched

| File | Change |
|------|--------|
| `config.go` | `IpResolution` struct, defaults, validation, `auth.ip_header` deprecation shim |
| `http.go` | `/resolve` handler; probe JS in both `indexTempl` and `noAuthTempl` |
| `user.go` | resolution order in `finishUser`; family determination |
| `whitelist.go` | family-aware `add()` |
| `redis.go` | `redisKey` / `baseKey`; `getGroups` normalisation |
| `config/config.yaml` | new block; fix the now-false "A user has one IP" comment at :79 |
| `README.md` | document `ip_resolution`, the trust implication of `url`, deprecate `ip_header` |
| `config.dev/config.yaml` | gitignored — local only, easy to forget |

The Helm chart needs no changes: `templates/config.yaml` passes `.Values.config`
through verbatim.

## Testing

- **`config_test.go`** — defaults with no block; `*bool` semantics (unset vs
  `false`); fatal when both families disabled; fatal on `url` with a disabled
  family; `url_timeout` parsing, its `5s` default, and fatals on an unparseable
  value, a non-positive value, and `url_timeout` without `url`;
  `auth.ip_header` fallback and its deprecation warning.
- **`redis_test.go`** — per-family keys; independent TTLs; `getGroups`
  normalisation through `baseKey`.
- **`whitelist_test.go`** — an IPv6 entry does not clobber the same user's IPv4
  entry; `add()` per-family change detection.
- **`http_test.go`** — `/resolve` accepts a valid claim; rejects a family
  mismatch, an unparseable IP, a disabled family, and a family with no `url`
  configured; rejects an unauthenticated caller; prefers the observed address
  when the request arrives over the claimed family.
- **`functions_test.go`** — `redisKey` / `baseKey` round-trip, including the
  IPv6-address-as-key case from `auth.type: none`.

## Out of scope

- A self-hosted family-pinned echo endpoint, and the nonce mechanism it would
  need behind Cloudflare Access (decision 3).
- Any change to per-resource `ip_version` semantics.
- Verifying that a target service actually accepts the family we send it —
  `ip_resolution` and `ip_version` both control what the app *sends*, not what
  the service accepts. Unchanged from PR #8.
