# IP Whitelister

Self-hosted web app that lets users authenticate with their AzureAD account and
temporarily whitelist their public IP against a configurable set of cloud
resources. Whitelistings expire automatically after a configurable TTL (default
24 hours), so firewall rules stay clean without manual cleanup.

Typical use case: give engineers self-service, time-limited access to
IP-restricted Azure resources (databases, storage, Key Vault, etc.) without
handing out standing firewall exceptions or VPN access.

## How it works

1. User opens the web UI and authenticates with AzureAD (OAuth2 authorization
   code flow).
2. Their public IP is detected and shown.
3. On whitelist, the IP is:
   - skipped if it already falls within the static `ip_whitelist`;
   - stored in Redis against the user, with a TTL;
   - pushed as a firewall rule to every configured cloud resource (optionally
     gated by AzureAD group membership per resource).
4. A background sync re-applies the whitelist hourly. As Redis entries expire,
   the corresponding IPs drop out of the resource firewall rules on the next
   sync.

## Cloud / resource support

**Azure:**
- FrontDoor (WAF policy)
- Storage Account
- Key Vault
- Postgres Server
- Redis Cache
- Cosmos DB

**UniFi:**
- Network List (firewall address-group) — see [UniFi](#unifi) below

### Group support

Each resource can specify a list of AzureAD group object IDs. A user is only
whitelisted against that resource if they belong to at least one of the listed
groups. If no groups are specified, all authenticated users are whitelisted
against the resource.

## Requirements

- An AzureAD App Registration / Service Principal with:
  - permission to update the target Azure resources, and
  - Admin Consent for AzureAD sign-in.
- A Redis instance (tracks per-user IP TTLs).

## Configuration

The app is configured via a YAML file (see [`config/config.yaml`](config/config.yaml)
for a complete example). The config is hot-reloaded on change — no restart
required.

Key top-level options:

| Key            | Description                                                        |
| -------------- | ------------------------------------------------------------------ |
| `url`          | Public base URL of the app (used to build the OAuth callback).     |
| `ttl`          | Whitelist lifetime in hours (default `24`).                        |
| `auth`         | Authentication mode: `type: azure` (AzureAD OAuth) or `type: none` (disable in-app auth — see [Disabling auth](#disabling-auth-reverse-proxy-sso)). |
| `redis`        | Redis `host`, `port`, and `token`.                                 |
| `unifi`        | UniFi gateway connection + credentials (see [UniFi](#unifi)).       |
| `resources`    | List of cloud resources to whitelist against (see example config). |
| `ip_whitelist` | Static, always-applied IPs — for non-human/proxy addresses only.   |
| `ip_version`   | Per-resource address family: `ipv4` (default), `ipv6`, or `both`. |

### Address families (`ip_version`)

Each entry in `resources` takes an optional `ip_version`:

| Value  | Effect                                              |
| ------ | --------------------------------------------------- |
| `ipv4` | Only IPv4 addresses are whitelisted. **Default.**   |
| `ipv6` | Only IPv6 addresses are whitelisted.                |
| `both` | Both families are whitelisted.                      |

A user has a single whitelisted IP — whichever family their browser reached the
app over — so an IPv4 user never appears in an `ipv6` resource, and vice versa.
To cover both, whitelist against two resources.

**Exception:** `azure` / `frontdoor` defaults to `both`, because it has never
filtered by address family. Set `ip_version: ipv4` explicitly to restrict it.

Note that not every backing service accepts IPv6 — Azure Key Vault firewall
rules, for example, are IPv4-only. `ip_version` filters what the app sends; it
does not check what the service accepts.

### Secrets via environment variables

Sensitive values can be injected via env vars, overriding the YAML:

| Variable        | Overrides / effect                                    |
| --------------- | ----------------------------------------------------- |
| `CONFIG_FILE`   | Path to the config file.                              |
| `CLIENT_SECRET` | `auth.client_secret`.                                 |
| `REDIS_TOKEN`   | `redis.token`.                                        |
| `UNIFI_USERNAME`| `unifi.username`.                                     |
| `UNIFI_PASSWORD`| `unifi.password`.                                     |
| `DEBUG`         | Set to `true` for verbose debug logging.              |

> **Note:** as a safety guard, Azure resource updates are a no-op while the auth
> `tenant_id` is left as the placeholder value from the sample config, and UniFi
> syncing is skipped while `unifi.host` is empty or contains `notreal`, so the
> dummy config never touches real cloud resources or a real gateway.

### Disabling auth (reverse-proxy SSO)

If you run ip-whitelister behind an SSO reverse proxy (e.g. Cloudflare Access,
Authelia, oauth2-proxy) you can disable the built-in AzureAD login and let the
proxy handle authentication:

```yaml
auth:
  type: none   # alias: disabled
  # header:    Cf-Access-Authenticated-User-Email   # trusted identity header (default shown)
  # ip_header: Cf-Connecting-Ip                      # trusted client-IP header (default shown)
```

In this mode any request to `/` immediately whitelists the caller's IP and shows
a confirmation page — there is no OAuth redirect or callback. The whitelist
entry is keyed on the identity the proxy supplies in the configured `header`
(default `Cf-Access-Authenticated-User-Email`); if that header is absent the
entry is keyed on the client IP instead.

The client IP is read from the header named by `ip_resolution` (see below).
`auth.ip_header` is **deprecated** but still honoured as a fallback for any
family that names no header of its own. **Your proxy MUST set this header to the
real client IP and strip any client-supplied value** — otherwise an
authenticated user could spoof it to whitelist an arbitrary address. For Azure
Front Door use `X-Azure-Clientip`.

Because AzureAD group membership is unavailable without OAuth, **group-scoped
resources are skipped** in this mode — only resources without a `group:` filter
are whitelisted. `tenant_id`, `client_id` and `client_secret` are ignored and
can be omitted.

### Dual-stack (`ip_resolution`)

A request only reveals the address family the browser connected over, so a
dual-stack user is normally whitelisted for one family only — in practice IPv6,
which browsers prefer. `ip_resolution` describes how to learn an address for
each family:

```yaml
ip_resolution:
  ipv4:
    enabled: true                     # default true
    header: Cf-Connecting-Ip          # trusted client-IP header
    url: https://ipv4.icanhazip.com   # optional, see below
    url_timeout: 5s                   # optional, default 5s
  ipv6:
    enabled: true
    header: Cf-Connecting-Ip
    url: https://ipv6.icanhazip.com
    url_timeout: 5s
```

Omitting the block entirely reproduces the previous behaviour: both families are
enabled, and whichever family the browser connected over is recorded. Each
family gets its own Redis entry and its own TTL, so one expiring does not
disturb the other.

This controls what the app **collects**. A resource's `ip_version` controls
where it is **sent** — the two are independent, and an IPv6 address still only
reaches resources configured for `ipv6` or `both`.

**`header` is trusted; `url` is not.** A header value is observed by the app or
its proxy and cannot be forged. A `url` is a family-pinned echo service fetched
**by the browser**, whose answer is POSTed back to `/resolve` — so the address
arrives as a *claim*. An authenticated user can fabricate it and whitelist an
address they do not control. Setting `url` is the opt-in to that trade-off; the
app logs which families use it at startup. Where the app can see the address
itself, the observed value always wins over the claim.

The echo service must send `Access-Control-Allow-Origin` or the browser will
refuse to read the response; `icanhazip.com` does. Note that it will learn your
hostname (via the `Origin` header) and the user's IP. No cookies or auth headers
are sent to it.

### UniFi

The `unifi` provider keeps a UniFi **Network List** (a firewall address-group) in
sync with the current whitelist. Point a port-forward rule's **From: List** at
that Network List and its allowed source IPs will track whitelisted users — the
app only ever manages the list's members, not the rule itself.

Configure the single gateway once, then add a `networklist` resource per list:

```yaml
unifi:
  host: https://192.168.1.1   # gateway base URL
  site: default               # UniFi site name
  username: ip-whitelister    # dedicated limited local account (not your admin login)
  password: changeme          # or via env var UNIFI_PASSWORD

resources:
  - cloud: unifi
    type: networklist
    name: ip-whitelister      # the Network List to manage
    group:                    # optional: only whitelist users in these AzureAD groups
      - <group-object-id>
    ip_whitelist:             # optional: per-list static entries
      - 1.2.3.4/32

  # a UniFi Network List is family-typed, so IPv6 needs its own list
  - cloud: unifi
    type: networklist
    name: ip-whitelister-ipv6
    ip_version: ipv6
```

Setup notes:
- Create the Network List and set the port-forward's **From: List** to it once in
  the UniFi UI; the app manages only the list members.
- Use a dedicated limited local UniFi account, not your main admin login.
- Credentials are best injected via `UNIFI_USERNAME` / `UNIFI_PASSWORD`.
- IPv4 only for now.

## Docker image

Published to GitHub Container Registry:

```
ghcr.io/alec-pinson/ip-whitelister
```

<https://github.com/alec-pinson/ip-whitelister/pkgs/container/ip-whitelister>

## Deployment

### Docker Compose

1. Configure a config file — see [`config/config.yaml`](config/config.yaml).
2. Check / reconfigure [`docker-compose.yaml`](docker-compose.yaml).
3. Run `docker-compose up -d`.

### Helm

See the [chart README](helm/ip-whitelister/README.md).

## Health endpoints

The app listens on port `8080` and exposes:

- `GET /live` — liveness probe
- `GET /ready` — readiness probe

## Development

```sh
go build ./...   # build
go vet ./...     # static checks
go test ./...    # tests (spins up Redis via dockertest)
```

## License

IP Whitelister is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE).

- **Free for noncommercial use** — homelabs, personal projects, students, nonprofits, educational and government institutions.
- **Commercial/company use requires a paid license.** If your organisation wants to use IP Whitelister, please get in touch to arrange a commercial licence.

Copyright © 2021-2026 Alec Pinson.
