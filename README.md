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
| `auth`         | AzureAD tenant/client credentials (`type: azure`).                 |
| `redis`        | Redis `host`, `port`, and `token`.                                 |
| `resources`    | List of cloud resources to whitelist against (see example config). |
| `ip_whitelist` | Static, always-applied IPs — for non-human/proxy addresses only.   |

### Secrets via environment variables

Sensitive values can be injected via env vars, overriding the YAML:

| Variable        | Overrides / effect                                    |
| --------------- | ----------------------------------------------------- |
| `CONFIG_FILE`   | Path to the config file.                              |
| `CLIENT_SECRET` | `auth.client_secret`.                                 |
| `REDIS_TOKEN`   | `redis.token`.                                        |
| `DEBUG`         | Set to `true` for verbose debug logging.              |

> **Note:** as a safety guard, resource updates are a no-op while the auth
> `tenant_id` is left as the placeholder value from the sample config, so the
> dummy config never touches real cloud resources.

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
