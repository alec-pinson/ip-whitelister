# IPv6 support via a shared `ip_version` resource field — design

**Date:** 2026-08-24
**Status:** Approved (design)
**Author:** Alec Pinson

## Summary

Add a provider-agnostic `ip_version` field to every resource in `config.yaml`,
selecting which IP address family that resource is whitelisted for: `ipv4`
(default), `ipv6`, or `both`. This unlocks the driving use case — syncing a
user's IPv6 address into a UniFi **Network List** of type `ipv6-address-group`
— without inventing per-provider type names, and gives every current and future
provider the same knob.

```yaml
resources:
  - cloud: unifi
    type: networklist
    name: usenetstreamer-allow-list-ipv4   # ip_version omitted => ipv4

  - cloud: unifi
    type: networklist
    ip_version: ipv6
    name: usenetstreamer-allow-list-ipv6

  - cloud: unifi
    type: networklist
    ip_version: both
    name: mixed-example
```

Along the way this fixes two pre-existing IPv6 defects found while designing
(see **Defects absorbed**).

## Motivation

`user.finishUser()` already stores an IPv6 client correctly — `addNetmask()`
gives it a `/128` and it goes into Redis like any other address. But every
resource then discards it: all six Azure types guard with
`isValidIpOrNetV4()`, and `UnifiNetworkList.buildMembers()` does the same. An
IPv6-connecting user is silently whitelisted nowhere.

UniFi firewall groups are family-typed (`address-group` vs
`ipv6-address-group`), so an IPv6 Network List is a real, separate list that
needs IPv6 members pushed to it.

## Decisions

Settled during brainstorming, recorded here because each rules out an
alternative that looks reasonable in isolation:

1. **A shared `ip_version` field, not new type names.** An earlier sketch used
   `type: networklist-ipv4` / `networklist-ipv6`. A field applies uniformly to
   all providers and does not multiply type names per family.

2. **Default is `ipv4`.** Preserves today's behaviour on upgrade for every
   resource type (see #3 for the one exception this required). `ipv6` and
   `both` are opt-in.

3. **Front Door defaults to `both`.** Front Door is the only resource type with
   *no* family filter today (`azure.go:134` omits the `isValidIpOrNetV4` guard
   the other five Azure types have), so it currently passes IPv6 through. A flat
   `ipv4` default would silently stop whitelisting IPv6 users there. Defaulting
   just this type to `both` makes the upgrade a true no-op for all seven types.

4. **No capability table and no `group_type` verification.** `ip_version` is a
   pure filter over the whitelist. Setting `ip_version: ipv6` on a resource
   whose backing service is IPv4-only (Key Vault is documented IPv4-only) is
   the operator's call, not something the app polices. `getFirewallGroup()`
   continues to match on name alone.

5. **One IP per user — no dual-stack capture.** `w.List` holds a single address
   per user, whichever family their browser reached the app over. An
   IPv4-connecting user therefore never appears in an IPv6 list. Capturing both
   families would need a client-side probe and a Redis schema change; explicitly
   out of scope.

6. **`ip_version` is not added to per-file `Defaults`.** YAGNI; `Defaults`
   stays `subscription_id` / `resource_group`.

## Design

### Config

`ResourceConfiguration` gains one field:

```go
type ResourceConfiguration struct {
	// ...
	IPVersion string `yaml:"ip_version"` // ipv4 (default) | ipv6 | both
}
```

`config.load()` lowercases the value and validates it against
`{"", "ipv4", "ipv6", "both"}`, calling `log.Fatalln` on anything else — the
same failure style already used for an unsupported `cloud` or `type`. Each of
the seven `case` arms copies `resource.IPVersion` onto its resource struct; the
Front Door arm substitutes `both` when the field is empty (decision #3).

### The filter

One helper in `functions.go` replaces `isValidIpOrNetV4` at all twelve call
sites. `isValidIpOrNetV4` is deleted and its test converted.

```go
// matchesIpVersion reports whether ip is a parseable address of the family
// selected by a resource's ip_version. An empty want means ipv4.
func matchesIpVersion(want, ip string) bool {
	t, err := ipVersion(ip)
	if err != nil {
		return false
	}
	switch want {
	case "ipv6":
		return t == IpV6
	case "both":
		return true
	default:
		return t == IpV4
	}
}
```

It keeps `isValidIpOrNetV4`'s existing contract for unparseable input —
`ipVersion()` already logs and returns an error, and the helper returns false —
so no caller gains a new failure mode.

### Resource structs and call sites

The six Azure structs and `UnifiNetworkList` each gain an `IPVersion string`
field. Guards become `matchesIpVersion(nl.IPVersion, ip)`:

| file | sites | change |
|---|---|---|
| `azure.go` | 10 | `isValidIpOrNetV4(x)` → `matchesIpVersion(<res>.IPVersion, x)` |
| `azure.go:134` | 1 | Front Door — **add** the missing guard |
| `unifi.go` | 2 | `buildMembers` dynamic + static loops |

### UniFi member format

`unifiMember()` strips `/128` alongside `/32`, by symmetry with the existing
IPv4 reasoning (UniFi stores single hosts bare, and matching its stored form
keeps `sameMembers()` stable so an unchanged whitelist doesn't force a PUT
every reconcile).

**Unverified against a live gateway.** This is the same open item already
tracked for the `/32` behaviour and the `group_type` string values; it folds
into the outstanding UniFi live-gateway validation task rather than blocking
this work.

## Defects absorbed

Both are pre-existing, both are IPv6-specific, and both become reachable the
moment `ip_version` can be set to `ipv6` or `both`.

### 1. Front Door has no family filter

`azure.go:134` is the only whitelist guard in the codebase without a family
check. IPv6 addresses already flow into Front Door WAF custom rules today.
Adding the guard (defaulted to `both`) makes the behaviour explicit and
configurable without changing it.

Note: Microsoft's docs confirm Key Vault is IPv4-only but state nothing either
way about Front Door WAF `IPMatch` and IPv6. The existing code assumes IPv6
works there; this design preserves that assumption rather than betting against
it.

### 2. `getIpList` silently corrupts IPv6

`binary.BigEndian.Uint32(ipv4Net.Mask)` reads the first four bytes of what is a
sixteen-byte mask for IPv6, and `Uint32(ipv4Net.IP)` the first four bytes of the
address. No panic — just a wrong `first` and `last`, fed to StorageAccount,
Postgres, RedisCache and CosmosDb.

The fix is to **stop enumerating** rather than to extend enumeration to IPv6:

- Nothing consumes the `all` return. All six Azure call sites are
  `first, last, _ := getIpList(...)`; only `functions_test.go` reads it.
- Enumeration cannot survive IPv6 — a `/64` is 1.8×10¹⁹ addresses — and is
  already a latent problem for IPv4 (a `/8` allocates 16M strings).

So `getIpList` is replaced by:

```go
// ipRange returns the first and last address of cidr. Works for IPv4 and IPv6;
// a bare address is its own first and last.
func ipRange(cidr string) (first, last string, err error)
```

computing the bounds by byte-wise mask math on `net.IPNet` (`ip[i] & mask[i]`
and `ip[i] | ^mask[i]`), which is family-agnostic. The `log.Fatal` on an
unparseable CIDR becomes a returned error — a bad config value should not take
the process down mid-reconcile. Six call sites and `TestGetIpList` are updated.

## Testing

`matchesIpVersion` and `ipRange` are pure functions, so the meaningful coverage
is cheap and needs neither Redis nor Docker.

- **`functions_test.go`** — table test for `matchesIpVersion` across
  `{ipv4, ipv6, both, ""}` × `{v4 bare, v4 CIDR, v6 bare, v6 CIDR, garbage}`.
- **`functions_test.go`** — `ipRange` for a v4 CIDR (preserving the existing
  expectations), a v6 CIDR, bare addresses of both families, and an
  unparseable value returning an error rather than exiting.
- **`config_test.go`** — `ip_version` parses and lowercases; empty defaults to
  `ipv4`; empty on a Front Door resource defaults to `both`; an invalid value
  is rejected.
- **`unifi_test.go`** — extends the existing `buildMembers` tests behind the
  `unifiClient` seam: an `ipv6` list excludes v4 members, `/128` is stripped,
  and `both` keeps addresses of both families.

Azure stays untested, per the existing decision recorded in the workspace notes
(globals, no client seam; no provider-interface refactor before a third
provider). Its behaviour here rides entirely on `matchesIpVersion` and
`ipRange`, both of which are directly covered.

## Documentation

- `config/config.yaml` and `config.dev/config.yaml` — document `ip_version` on
  the sample resources, including a UniFi IPv6 Network List example.
- `README.md` — add `ip_version` to the resource field reference, noting the
  `ipv4` default and the Front Door `both` exception.
- `helm/ip-whitelister/README.md` — update if it documents resource fields.

## Out of scope

- Dual-stack capture of both families per user (decision #5).
- Verifying a UniFi group's `group_type` against the configured `ip_version`
  (decision #4).
- Live-gateway validation of the `/128` member format — tracked with the
  existing UniFi validation item.
- Any Azure provider-interface refactor.
