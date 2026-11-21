# Broker reference

## Commands and flags

```
gh-appauth-broker serve [flags]
  -data-dir DIR        directory for broker.db (default data/ next to the binary)
  -db FILE             SQLite database file, overrides -data-dir
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
  -tokens-per-minute N  token requests and repo listings per minute per client (default 60)
  -oidc-issuer URL     turn on single sign-on to the admin UI (see below)
  -oidc-client-id ID
  -oidc-client-secret-file FILE  omit for a public client
  -oidc-redirect-url URL         public URL of the UI plus /ui/oidc/callback
  -oidc-allowed-groups LIST      required with -oidc-issuer
  -oidc-groups-claim NAME        default groups
  -oidc-scopes LIST              default profile,email,groups; openid is always added
  -oidc-name TEXT                provider name on the sign-in button (default SSO)

gh-appauth-broker set-password               admin UI password (stdin; ≥10 chars; logs out all sessions)
gh-appauth-broker set-password -clear        remove the password, leaving only single sign-on
gh-appauth-broker check                      validate stored config and keys
gh-appauth-broker fingerprint                self-signed certificate SHA-256
(all of these also take -data-dir DIR or -db FILE)
gh-appauth-broker version                    print the version (also shown in the admin UI)
```

### Environment variables

Every flag can also be set from an environment variable named `GH_APPAUTH_BROKER_` plus the flag name in upper case with `-` turned into `_`: `-data-dir` is `GH_APPAUTH_BROKER_DATA_DIR`, `-ui-listen` is `GH_APPAUTH_BROKER_UI_LISTEN`, `-tokens-per-minute` is `GH_APPAUTH_BROKER_TOKENS_PER_MINUTE`. `-h` lists the name next to each flag.

A flag on the command line wins over the environment, and the environment wins over the built-in default. That includes `-db` and `-data-dir`: `-data-dir` on the command line beats `GH_APPAUTH_BROKER_DB`. A variable that is set but empty counts as unset. An invalid value stops the broker with an error that names the variable. A variable applies to every command with that flag, so `GH_APPAUTH_BROKER_TLS_CERT` also makes `fingerprint` show that certificate.

This is handy in containers. For example, in a Docker Compose service:

```yaml
    command: ["gh-appauth-broker", "serve"]
    environment:
      GH_APPAUTH_BROKER_DATA_DIR: /data
      GH_APPAUTH_BROKER_UI_LISTEN: "off"
      GH_APPAUTH_BROKER_TOKENS_PER_MINUTE: "240"
```

No flag takes a secret as its value. The OIDC client secret is read from a file, so `GH_APPAUTH_BROKER_OIDC_CLIENT_SECRET_FILE` holds a path, which works with Docker and Compose secrets.

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
| Clients | Create, disable or delete clients, IP allowlists, secrets (generate, rotate, remove) with the setup command for the client machine, grants (ordered; first match wins), per-client tokens and history. |
| Apps | Add or replace Apps (paste or upload a `.pem`), test them against GitHub, delete Apps that no grant uses. |
| History | Every token request, repo listing, denial, error, revocation, invalidation and admin UI sign-in, filterable by client, event and repo. |
| Settings | Server settings (read-only), TLS fingerprint, single sign-on status, sign out all sessions, password change. |

The UI requires the admin password or [single sign-on](#single-sign-on-oidc). Sessions last 12 hours and are stored in SQLite. Forms carry CSRF tokens, the session cookie is `SameSite=Strict`, and a strict CSP is set. The session cookie is `Secure` when the broker serves TLS, or when a trusted proxy (`-trusted-proxies`) sends `X-Forwarded-Proto: https`. Failed logins are limited per source address (per /64 for IPv6), separately from API authentication failures.

To keep the UI away from agents, put it on its own port, for example `-ui-listen 127.0.0.1:8444`, and reach it through an SSH tunnel, or firewall that port.

The UI can be installed as an app (a PWA) from Chrome, Edge or Safari's install or "Add to Dock / Home Screen" option. Browsers allow this only on a secure origin: HTTPS with a certificate the browser trusts, or `http://localhost`, which includes an SSH tunnel to a local port. The installed app opens in its own window at `/ui/`. It caches nothing. Its service worker only shows an offline page when the broker can't be reached.

## Single sign-on (OIDC)

The admin UI can sign in through any OpenID Connect provider. Register the broker there as a web application using the authorization code flow, with the redirect URL `https://BROKER/ui/oidc/callback` (the address your browser uses for the UI), then start the broker with:

```
-oidc-issuer https://id.example.com
-oidc-client-id gh-appauth
-oidc-client-secret-file /etc/gh-appauth/oidc-secret
-oidc-redirect-url https://broker.example.com:8444/ui/oidc/callback
-oidc-allowed-groups broker-admins
```

`-oidc-issuer` has to match the `issuer` in the provider's discovery document exactly, trailing slash included. The issuer and redirect URL must use `https://`, except on localhost. The secret file is read once at startup and a trailing newline is ignored. Leave out `-oidc-client-secret-file` for a public client, which then relies on PKCE alone. The broker always uses PKCE. Starting with any `-oidc-*` flag but no issuer, with `-ui-listen off`, or without `-oidc-allowed-groups` is an error.

**Who gets in.** The broker reads the claim named by `-oidc-groups-claim` from the ID token. If the ID token has no such claim, it asks the userinfo endpoint, whose `sub` must match the ID token's. Membership in any one of `-oidc-allowed-groups` signs the user in; names are compared exactly, case included. The claim may be a list of strings, a single string, or an object whose keys are the group names (as in Zitadel's role claims). Anything else counts as no groups, and a claim that is present but empty is not looked up in userinfo. Everyone who gets in shares the one admin account. The name they signed in with (`preferred_username`, else `email`, `name` or `sub`) is shown as "Signed in as" and recorded as a `ui_login` event in the history. A refused sign-in is recorded as `denied`.

**Password and SSO together.** Password sign-in stays available as long as a password is set. `gh-appauth-broker set-password -clear` removes it, leaving SSO as the only way in. To get back in when the provider is down, run `set-password` on the broker host; it takes effect at once, without a restart. When no password is set, an admin signed in through SSO can set one on the Settings page. Setting or changing the password is recorded as a `ui_password` event.

**Redirects.** With SSO configured, `/ui/login` goes straight to the provider. It shows the sign-in page instead after you sign out or a sign-in fails, while the provider can't be reached, and when the URL has `?password` (`/ui/login?password`), which shows the password form. The page links there when a password is set. The broker looks up the provider in the background at startup and logs the result; while that fails, it tries again on a sign-in at most every 10 seconds. The token API never waits for the provider. Open the UI on the same host name as the redirect URL: the sign-in cookie belongs to one host, so starting at `127.0.0.1` with a `localhost` redirect URL ends in "Sign-in expired".

**Revocation.** Removing someone from the group only stops their next sign-in. Sessions last 12 hours; "Sign out all sessions" on the Settings page ends every open one. Signing out of the broker does not sign you out of the provider. Anyone signed in can set or change the admin password, so when you remove someone, also change the password if one is set (or clear it with `set-password -clear`).

Two warnings:

- The groups claim must be one only the provider's administrators control, never an attribute users can edit themselves. A provider with open self-registration is fine only if users can't add themselves to the group.
- In Zitadel, if the project is granted to other organizations, their administrators can assign its roles, and with them access to the broker.

## HTTP API

| Method / path | Auth | |
|---|---|---|
| `GET /healthz` | none | `ok` |
| `POST /v1/token` | `Bearer <secret>` | `{"repository":"owner/repo","permissions":{…}?}` → token, expiry, App, permissions, bot name and email |
| `POST /v1/invalidate` | Bearer | `{"token":"ghs_…"}`. GitHub rejected this token, so don't serve it from cache again (sent by `git credential reject` and the `gh` shim). A token that was already revoked stays as it is; the history records the report with the original reason. |
| `GET /v1/whoami` | Bearer | client name, the IP the broker sees, grants |
| `GET /v1/repos?owner=OWNER` | Bearer | `{"repos":[{"full_name","default_branch","private","archived","app"}]}`: OWNER's repos this client can get a token for, meaning its first matching grant names an App whose installation can access the repo. To list them, the broker mints a metadata-only token for each such App's whole installation and revokes it right after. That token never leaves the broker. Counts toward the token rate limit. |

Error codes:

| Code | Meaning |
|---|---|
| `400` | Bad body, repo name or owner. |
| `401` | Unknown or disabled secret. |
| `403` | No grant, permission escalation, wrong source IP, or the App isn't installed on that repo. |
| `429` | Rate limited: by default 60 token requests and repo listings per minute per client (set with `-tokens-per-minute`), or about 20 failed authentications per minute per IP (per /64 for IPv6). A limited address is refused even with a valid secret. |
| `502` | GitHub returned an error. |

## Caching

The broker reuses a token while it has more than 10 minutes left. Installation IDs are cached per owner for an hour, and bot identities are cached too. A failed identity lookup is retried at most every 5 minutes and never fails the token request.
