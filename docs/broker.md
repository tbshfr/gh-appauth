# Broker reference

## Commands and flags

```
gh-appauth-broker serve [flags]
  -data-dir DIR        directory for broker.db (default data/ next to the binary, env GH_APPAUTH_BROKER_DATA_DIR)
  -db FILE             SQLite database file, overrides -data-dir (env GH_APPAUTH_BROKER_DB)
  -listen ADDR         API address, host:port or unix:/path (default :8443)
  -ui-listen ADDR      admin UI: ""  = under /ui/ on the API port (default)
                                 "off" = disabled
                                 host:port = separate listener, e.g. 127.0.0.1:8444
  -tls MODE            self (default) | files | off
  -tls-cert/-tls-key   PEM files for -tls files (reloaded on SIGHUP)
  -tls-hosts LIST      names/IPs for the self-signed certificate
  -trusted-proxies LIST  CIDRs whose X-Forwarded-For is trusted (default: none, header ignored)
  -github-api URL      default https://api.github.com (GitHub Enterprise: https://HOST/api/v3)
  -history-days N      request history retention (default 30)

gh-appauth-broker set-password               admin UI password (stdin; ≥10 chars; logs out all sessions)
gh-appauth-broker check                      validate stored config and keys
gh-appauth-broker fingerprint                self-signed certificate SHA-256
(all of these also take -data-dir DIR or -db FILE)
gh-appauth-broker version                    print the version (also shown in the admin UI)
```

## TLS modes

| Mode | What happens | Client setup |
|---|---|---|
| `self` (default) | On first start, generates a 10-year ECDSA certificate and keeps it in the database, so the fingerprint stays the same across restarts. If you pass `-tls-hosts` with names the current certificate doesn't cover, a new certificate is generated. | `--fingerprint <SHA-256>` pins that exact certificate. |
| `files` | Uses your certificate and key (from an internal CA, `tailscale cert`, Let's Encrypt and so on). SIGHUP reloads them. | Nothing extra for a public CA. For an internal CA, use `--ca-file ca.pem`. |
| `off` | Plain HTTP. The broker logs a warning when it's on a non-loopback address. | `--insecure-http`, required for any non-loopback `http://` URL. |

Clients never turn verification off. With `--fingerprint`, the certificate has to match the pinned hash exactly, which is stricter than validating against a CA. If you run `setup` against an untrusted certificate, it prints that certificate's fingerprint so you can compare it and pin it.

## Admin UI

| Page | What's there |
|---|---|
| Dashboard | Counts for the last 24 hours, active tokens (client, repo, App, permissions, expiry, reuse count, Revoke button), recent requests. |
| Clients | Create, disable or delete clients, IP allowlists, secrets (generate, rotate, remove), grants (ordered; first match wins), per-client tokens and history. |
| Apps | Add or replace Apps (paste or upload a `.pem`), test them against GitHub, delete Apps that no grant uses. |
| History | Every token request, repo listing, denial, error, revocation and invalidation, filterable by client, event and repo. |
| Settings | Server settings (read-only), TLS fingerprint, the client setup command, password change. |

The UI requires the admin password. Sessions last 12 hours and are stored in SQLite. Forms carry CSRF tokens, cookies are `SameSite=Strict`, and a strict CSP is set. The session cookie is `Secure` when the broker serves TLS, or when a trusted proxy (`-trusted-proxies`) sends `X-Forwarded-Proto: https`. Failed logins are limited per source address (per /64 for IPv6), separately from API authentication failures.

To keep the UI away from agents, put it on its own port, for example `-ui-listen 127.0.0.1:8444`, and reach it through an SSH tunnel, or firewall that port.

## HTTP API

| Method / path | Auth | |
|---|---|---|
| `GET /healthz` | none | `ok` |
| `POST /v1/token` | `Bearer <secret>` | `{"repository":"owner/repo","permissions":{…}?}` → token, expiry, App, permissions, bot name and email |
| `POST /v1/invalidate` | Bearer | `{"token":"ghs_…"}`. GitHub rejected this token, so don't serve it from cache again (sent by `git credential reject`). |
| `GET /v1/whoami` | Bearer | client name, the IP the broker sees, grants |
| `GET /v1/repos?owner=OWNER` | Bearer | `{"repos":[{"full_name","default_branch","private","archived","app"}]}`: OWNER's repos this client can get a token for, meaning its first matching grant names an App whose installation can access the repo. To list them, the broker mints a metadata-only token for each such App's whole installation and revokes it right after. That token never leaves the broker. Counts toward the token rate limit. |

Error codes:

| Code | Meaning |
|---|---|
| `400` | Bad body, repo name or owner. |
| `401` | Unknown or disabled secret. |
| `403` | No grant, permission escalation, wrong source IP, or the App isn't installed on that repo. |
| `429` | Rate limited: 60 token requests and repo listings per minute per client, or about 20 failed authentications per minute per IP (per /64 for IPv6). A limited address is refused even with a valid secret. |
| `502` | GitHub returned an error. |

## Caching

The broker reuses a token while it has more than 10 minutes left. Installation IDs are cached per owner for an hour, and bot identities are cached too. A failed identity lookup is retried at most every 5 minutes and never fails the token request.
