# Disable auth (`auth.type: none`) — design

**Date:** 2026-07-02
**Status:** Approved (design)
**Author:** Alec Pinson

## Summary

Add a no-auth authentication mode (`auth.type: none`, alias `disabled`) so the
app can run behind an external SSO reverse proxy (e.g. Cloudflare Access)
instead of doing its own AzureAD OAuth login. In this mode the app trusts that
the upstream proxy has already authenticated the request. On any request to `/`
it immediately whitelists the requester's public IP and shows a confirmation
page — no OAuth redirect, no callback, no Microsoft Graph calls.

The change is contained and mostly additive: the auth type is already dispatched
through a `switch` on `auth.type` (`http.go`), and the whitelisting mechanism
already derives the client IP from request headers, not from OAuth.

## Motivation

Personal need: run `ip-whitelister` with SSO provided by Cloudflare Access in
front of it, rather than configuring an AzureAD app registration for OAuth.
`auth.type` is currently effectively required to be `azure` — any other value
hits the `default` branch and `log.Fatalln`s.

## Background: what OAuth is coupled to today

Three places depend on Azure OAuth:

1. `Authentication.initAzure()` (`http.go`) — builds `oauthConfig`, **and**
   registers the HTTP handlers (`/live`, `/ready`, `/callback`, `/`) and starts
   the `:8090` listener.
2. `IndexHandler` (`http.go`) — redirects unauthenticated users to the Azure
   auth URL; the rendered page's JS uses the OAuth token to call Graph API for
   the display name.
3. `User.new(client, req)` (`user.go`) — uses the **OAuth client** to call Graph
   API for `displayName`, `employeeId`, and **group memberships**.

The client IP itself comes from `X-Azure-Clientip` / `RemoteAddr`
(`user.go`), independent of OAuth, so the actual whitelisting needs no auth.

The one capability lost without OAuth is **group-based whitelisting**
(`User.groups`), because groups are sourced from AzureAD.

## Key insight: group filtering already handles no-auth correctly

`hasGroup(resourceGroups, userGroups)` (`functions.go`):

```go
func hasGroup(resourceGroups []string, userGroups []string) bool {
	if resourceGroups == nil {
		return true            // ungrouped resource → whitelist everyone
	}
	for _, rg := range resourceGroups {
		for _, ug := range userGroups {
			if rg == ug {
				return true
			}
		}
	}
	return false               // grouped resource, no match → skip
}
```

If a no-auth user has `groups == nil`:
- **Ungrouped resources** (`Group == nil`) → whitelisted (correct).
- **Group-scoped resources** (`Group != nil`) → skipped, since an empty user
  group set never matches (correct — "skip group-scoped resources" per the
  design decision).

So the sync path needs **no changes**. Giving no-auth users empty groups
produces the desired behaviour for free.

## Design decisions

- **Identity key:** configurable trusted header, defaulting to
  `Cf-Access-Authenticated-User-Email`. This works with any reverse-proxy SSO,
  not just Cloudflare. If the header is absent/empty on a request, fall back to
  keying the whitelist entry on the client IP.
- **Groups:** in no-auth mode, group-scoped resources are skipped (a whitelisted
  IP only reaches ungrouped resources). Achieved by empty groups + existing
  `hasGroup`.

## Components / changes

### 1. Config (`config.go`, `http.go`)

- Add `Header string \`yaml:"header"\`` to the `Authentication` struct.
- In `config.load`, when `auth.type` is `none`/`disabled` and `header` is blank,
  default it to `Cf-Access-Authenticated-User-Email`.

### 2. Auth init (`http.go`)

- Add `case "none", "disabled":` to the `Authentication.init` switch → call a
  new `initNoAuth()`.
- `initNoAuth()` mirrors `initAzure()` minus OAuth: registers `/live`, `/ready`,
  and `/` → `noAuthIndexHandler` (no `/callback`, no `oauthConfig`, no session
  store), then `http.ListenAndServe(":8090", nil)`. Startup on `:8080` via the
  existing `start()` is unchanged.

### 3. Request handling (`http.go`)

- New `noAuthIndexHandler(w, req)`: builds a `User` from the request alone
  (`User.newFromRequest`), whitelists it (`u.whitelist()`), and renders a small
  confirmation page ("Your IP `x.x.x.x` has been whitelisted", plus the identity
  string when present). No redirect, no token, no Graph API JS. A dedicated,
  minimal template is used rather than reusing the OAuth-token-driven
  `indexTempl`.

### 4. User construction (`user.go`)

- Extract the shared tail of `User.new` (IP detection from
  `X-Azure-Clientip`/`RemoteAddr`, the `::1` local-testing override, `cidr`
  computation via `addNetmask`, and the key regex) into a helper method so both
  constructors share it.
- New `User.newFromRequest(req)` (no `*http.Client`):
  - identity = value of the configured header if present; else fall back to the
    client IP.
  - `groups = nil`.
  - key derived from the identity via the same regex normalisation as `new`.
  - reuse the shared helper for IP / cidr / key.
- `User.new` keeps calling Graph API and reuses the same shared helper.

### 5. Sync path — unchanged

Empty `groups` + existing `hasGroup` gives "skip group-scoped resources". The
`updateResources` guard keys off `c.Auth.TenantId` (the login tenant), which is
empty in no-auth mode, so resource sync proceeds normally.

## Data flow (no-auth mode)

1. Cloudflare Access (or another proxy) authenticates the user and forwards the
   request with the trusted identity header set.
2. User hits `/` → `noAuthIndexHandler`.
3. `User.newFromRequest(req)`: identity from header (or IP fallback), IP from
   request headers, `groups = nil`, key derived.
4. `u.whitelist()` → `Whitelist.add()`: stores user→CIDR (+ empty groups) in
   Redis with TTL, fires `updateResources()`.
5. Resources sync: ungrouped resources get the IP; group-scoped resources skip
   it.
6. Confirmation page renders.
7. Expiry unchanged: hourly `Whitelist.ttl()` re-push + Redis TTL.

## Error handling

- Missing identity header → fall back to IP-keyed entry (no error).
- IP detection unchanged from `User.new` (logs on `RemoteAddr` parse failure).
- Same `Whitelist.add` / Redis error paths as the existing flow.

## Testing

- `User.newFromRequest` (no Redis): header present → key from header; header
  absent → key from IP; IP detection precedence (`X-Azure-Clientip` vs
  `RemoteAddr`); `groups == nil`.
- `noAuthIndexHandler` via `httptest` + the existing `stubRedis` fake redis
  connection: a request whitelists and renders the confirmation page.
- Assert an empty-group user is skipped for a group-scoped resource (verify
  existing coverage; add if missing).
- Config: `auth.type: none` loads and defaults `header` to
  `Cf-Access-Authenticated-User-Email`.

## Out of scope

- Verifying the Cloudflare Access JWT (`Cf-Access-Jwt-Assertion`) signature. The
  app trusts the proxy; JWT validation can be a later hardening step.
- Any change to Azure OAuth behaviour or the Azure resource providers.
- Restoring group-based whitelisting in no-auth mode (groups require AzureAD).

## Files touched

- `http.go` — new `case`, `initNoAuth`, `noAuthIndexHandler`, confirmation
  template; `Authentication.Header` field.
- `user.go` — shared IP/key helper, `newFromRequest`.
- `config.go` — default header when `type: none`.
- README — document `auth.type: none` + `header`. The sample
  `config/config.yaml` stays on `azure`; no-auth is README-documented only.
- Tests as above.
