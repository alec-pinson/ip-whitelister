# UniFi Network List provider — design

**Date:** 2026-07-02
**Status:** Approved (design)
**Author:** Alec Pinson

## Summary

Add UniFi as the first non-Azure whitelist provider. A user's temporarily
whitelisted public IP is synced into a UniFi **Network List** (a firewall
address-group) on the user's Cloud Gateway. An existing port-forward rule
references that Network List via its **From: List** option, so maintaining the
list membership is all that is required to gate inbound access to the forwarded
port. The same temporary-TTL model as the Azure resources applies: expiry is
driven by the hourly `Whitelist.ttl()` re-push plus Redis TTL.

This is the first real use of the codebase's existing multi-provider seam
(`cloud:` field, `config.load()` `switch cloud → switch type`).

## Motivation

Personal need first: whitelist the current public IP against a specific
port-forward rule (e.g. `Allow-Kube-API-GitHub-IPv4`, WAN 20443 →
192.168.6.200:6443) on Alec's UniFi Cloud Gateway. Possible future product
feature. Lives in the PolyForm-Noncommercial repo `alec-pinson/ip-whitelister`.

## Background: how UniFi models this

Confirmed from the live UI and API docs:

- A **port-forward** rule has a **From** option: `Any` / `Limited` /
  `Specific` / **`List`**. When set to `List` it references a **Network List**.
- **Network Lists** are UniFi firewall **address groups** (`type:
  address-group` / `ipv6-address-group`) — a named list of IPs / subnets /
  ranges. Example existing lists: "GitHub Actions IPv4 Addresses" (4288 CIDRs),
  "Cameras", etc.
- Therefore restricting a port-forward's allowed source IPs == editing the
  members of the Network List it points at. No firewall zone / rule / policy
  manipulation is required by the app.

### API surface (MVP: legacy Network Application API)

The legacy Network Application API definitively supports editing address
groups (as wrapped by node-unifi / art-of-wifi/unifi-api-client):

- Auth: local account, `POST /api/auth/login` → session cookie + CSRF token.
- `GET /proxy/network/api/s/{site}/rest/firewallgroup` → find group by name,
  read `_id` + `group_members`.
- `PUT /proxy/network/api/s/{site}/rest/firewallgroup/{_id}` → write updated
  `group_members` (only when the desired set differs from current).

The newer official **Integration API** (`X-API-Key`, zone-based
`/firewall/policies`) is a documented future transport option, but its
address-group / Network List editing capability could not be confirmed from
docs and was not validated against a live gateway. The reconcile logic is
kept transport-agnostic (see below) so the Integration API can be added later
without touching provider logic.

## Design

### Data flow

Identical reconcile-to-Redis pattern as Azure providers. Redis is the source of
truth; the provider reconciles a UniFi Network List *to* it:

1. User authenticates (AzureAD) and whitelists → `Whitelist.add()` stores
   user→CIDR + user→groups in Redis with TTL, then `go w.updateResources()`.
2. `updateResources()` iterates every configured provider resource, now
   including UniFi Network Lists, calling each resource's `update()`.
3. `update()` computes the desired member set and, if it differs from the
   Network List's current members, issues one `PUT` to replace them.
4. Expiry: hourly `Whitelist.ttl()` → `updateResources()`; expired Redis
   entries naturally fall out of the desired set on the next sync.

### Configuration

Global `unifi:` block (mirrors `auth:` / `redis:`) providing gateway
connection + credentials, plus per-resource Network List entries using the
existing `cloud` / `type` seam:

```yaml
unifi:
  host: https://192.168.1.1     # gateway base URL
  site: default                 # UniFi site name
  username: ip-whitelister      # env override: UNIFI_USERNAME
  password: changeme            # env override: UNIFI_PASSWORD

resources:
  - cloud: unifi
    type: networklist
    name: ip-whitelister        # the Network List (firewall group) to manage
    group:                      # optional AzureAD group filter (reuses existing field)
      - <group-object-id>
    ip_whitelist:               # optional per-list static entries
      - 1.2.3.4/32
```

- Secrets injected via env vars following the existing
  `CLIENT_SECRET` / `REDIS_TOKEN` convention in `config.load()`:
  `UNIFI_USERNAME`, `UNIFI_PASSWORD` override the YAML values.
- **Safety guard** mirroring the `notreal-not-real-not-notreal` tenant guard:
  the UniFi loop in `updateResources()` is skipped when `unifi.host` is empty
  or the sample placeholder, so the dummy config never touches a real gateway.

### Code structure

Follows the Azure pattern exactly; does **not** refactor Azure into a provider
interface (rule of three — UniFi is only the 2nd provider; extract later when a
3rd lands).

- **`unifi.go`** (new): `Unifi` aggregate struct with a `NetworkList
  []UnifiNetworkList` field; `UnifiNetworkList` struct; `new()` and `update()`
  methods; package-level global `u Unifi` (parallels `a Azure`).
- **`config.go`**: add `Unifi` config struct + a `Unifi` field on
  `Configuration`; add `case "unifi"` → `case "networklist"` to the
  `config.load()` switch; add `UNIFI_USERNAME` / `UNIFI_PASSWORD` env overrides;
  reset `u.NetworkList = nil` alongside the existing `a.*` resets on reload.
- **`whitelist.go`**: add a UniFi loop to `updateResources()`
  (`for _, nl := range u.NetworkList { nl.update() }`) plus the host guard.

### Transport abstraction (testability)

`update()` depends on a small interface rather than raw HTTP, so the provider
gets the unit coverage the Azure code never had:

```go
type unifiFirewallGroup struct {
    ID        string   `json:"_id"`
    Name      string   `json:"name"`
    GroupType string   `json:"group_type"`
    Members   []string `json:"group_members"`
}

type unifiClient interface {
    getFirewallGroup(name string) (unifiFirewallGroup, error)
    updateFirewallGroup(g unifiFirewallGroup) error   // g carries id/name/group_type + new members
}
```

- Real implementation performs login (cookie + CSRF) and the `rest/firewallgroup`
  GET/PUT calls, using an injected `*http.Client` (allows `httptest`).
- Tests use a fake `unifiClient`, so `update()` reconcile logic is fully
  testable without a live gateway.

### Reconcile logic (`update()`)

Mirrors the Azure `update()` shape:

1. Build the desired member set:
   - For each `key, ip` in `w.List`: include when `!w.inRange(ip, nl.IPWhiteList)`
     **and** `isValidIpOrNetV4(ip)` **and** `hasGroup(nl.Group, r.getGroups(key))`.
     Debug-log skips for group mismatches (as Azure does).
   - Add static entries: `append(c.IPWhiteList, nl.IPWhiteList...)` filtered by
     `isValidIpOrNetV4`.
2. `getNetworkList(nl.Name)` → current `_id` + members.
3. If desired set != current set (order-insensitive compare) →
   `updateNetworkList(id, desired)`.
4. Idempotent; debug-gated logging of the member list; IPv4 only (matches Azure).

Member format (bare IP vs `/32`) to be confirmed against the live list during
validation; default to the stored CIDR and adjust if UniFi rejects it.

## Testing strategy

TDD with a fake `unifiClient`:

- Empty whitelist → empty (or static-only) member set.
- Group filter includes / excludes users correctly.
- Static `ip_whitelist` (global + per-list) included.
- No-op `PUT` when the desired set already matches current.
- Membership add and remove across syncs.
- IPv4-only filtering (IPv6 / invalid entries skipped).
- Login / HTTP error handling surfaces cleanly.

Final step: live validation against the real gateway — create a throwaway
`ip-whitelister` Network List, point a test port-forward's **From: List** at it,
and confirm end-to-end whitelist + expiry.

## Out of scope (fast-follows)

- IPv6 (`ipv6-address-group`) — MVP is IPv4 only, mirroring the Azure providers.
- App-managed firewall rules / port-forwards — the app owns list membership
  only; the user wires the port-forward to the list once in the UI.
- Integration API (`X-API-Key`) transport — kept as a future swap behind the
  `unifiClient` interface.
- Helm chart / README / sample-config documentation updates (handled in the
  implementation plan, not a design concern).
