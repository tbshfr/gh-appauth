# gh-appauth

> [!WARNING]
> **Experimental proof of concept.** The database schema, CLI and API may change without notice. Don't rely on it for anything important.

Gives coding agents (T3 Code, Claude Code and others) GitHub access through **GitHub Apps**, while the App private keys stay off the agent's machine.

```
 agent machine(s)                                       │  broker host
 agent ──git push──▶ git credential helper ─┐           │
 agent ──gh pr ...─▶ gh shim ───────────────┼─▶ gh-appauth ══HTTP(S) + client secret══▶ broker ──App JWT──▶ api.github.com
                                            │   (local token cache)                │  SQLite: App keys, clients,
                                            └ token for one repo, ≤1h, narrowed    │  grants, tokens, history
```

The repo builds two programs:

| Binary | What it is |
|---|---|
| `gh-appauth-broker` | A small HTTP service with an admin web UI. It holds the App keys in SQLite and issues short-lived installation tokens, each limited to one repo. |
| `gh-appauth` | A `gh` CLI extension (`gh appauth …`) that sets up plain `git` and `gh` to fetch tokens from the broker. Standard library only. |

## Threat model

An agent that holds a client secret can still get tokens for the repos it's granted. The broker adds the following:

- The App private key can't be stolen from an agent machine.
- Each client has its own secret, and you can revoke it in one place (the UI or the database). Revoking a client, removing or narrowing a grant, or replacing an App also revokes the affected live tokens at GitHub.
- Permissions are capped per grant, and every token covers a single repo.
- The audit log is central: JSON lines on stdout, plus request history in the UI.
- Optionally, `allowed_cidrs` makes a copied secret useless from another address.

The client secret travels over the network. Use TLS (the default is a self-signed certificate) unless the network really is trusted, and don't expose the broker to the internet.

## Quick start

### 1. Broker host

```bash
go build -o gh-appauth-broker ./cmd/gh-appauth-broker   # or use a release binary
sudo install -m 0755 gh-appauth-broker /usr/local/bin/
sudo gh-appauth-broker set-password -data-dir /var/lib/gh-appauth-broker
sudo cp deploy/gh-appauth-broker.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now gh-appauth-broker
journalctl -u gh-appauth-broker | grep fingerprint     # note the TLS fingerprint
```

By default the broker keeps its database in a `data/` directory next to its binary (created with mode 0700). Use `-data-dir DIR` or `GH_APPAUTH_BROKER_DATA_DIR` to put it somewhere else. The example unit runs under `DynamicUser=`, which can't write next to the binary, so it uses `-data-dir /var/lib/gh-appauth-broker` (its `StateDirectory=`). On first start systemd moves that directory to `/var/lib/private/` and gives it to the dynamic user, which is why `set-password` runs before the service is enabled. Change the password later on the Settings page.

Keep the clock in sync with chrony or systemd-timesyncd. GitHub rejects App JWTs from a clock that's more than about a minute off.

### 2. Create a GitHub App

In GitHub, go to Settings → Developer settings → GitHub Apps → New GitHub App:

- Turn off the webhook.
- Repository permissions: **Contents**, **Pull requests** and **Issues** set to read & write, and **Metadata** set to read. Add **Workflows** only if agents need to edit `.github/workflows`.
- Install the App on **selected repositories**.
- Generate a private key (`.pem`) and note the App ID.

### 3. Admin UI

The example unit serves the admin UI on its own port, bound to loopback (`-ui-listen 127.0.0.1:8444`), so agents that can reach the API port can't reach the login page. If the broker runs on another machine, change that to `-ui-listen 0.0.0.0:8444` in the unit and firewall the port so only your workstation can reach it. Then open `https://BROKER:8444/ui/` (or `https://localhost:8444/ui/` on the broker host) and sign in. With a self-signed certificate the browser shows a warning, and you can check the fingerprint against the one from step 1. Then:

1. **Apps**: add the App with a name, its App ID and the uploaded `.pem`. Click **Test** to confirm GitHub accepts the key.
2. **Clients**: create one client per agent or machine. The secret is shown **once**.
3. On the client page, add **grants**. Each grant has repo globs (`acme/api-*`), an App, and optional maximum permissions.

### 4. Agent machine

```bash
gh extension install tbshfr/gh-appauth           # or: go build && gh extension install .
gh appauth setup --broker https://broker.lan:8443 --fingerprint AB:CD:…   # paste the secret
gh appauth git-setup                              # git uses the broker for https://github.com
gh appauth shim ~/.local/gh-appauth-bin           # optional: plain `gh` uses App tokens
export PATH=~/.local/gh-appauth-bin:$PATH         # in the agent's environment
gh appauth status
```

After this, `git clone/fetch/push https://github.com/acme/api-core` and `gh pr create` work unchanged. To make commits show up as the App's bot, run `gh appauth identity` in the repo. It applies to all of the repo's worktrees.

The agent's OS user must have **no** `gh auth login` session. Then any `gh` call the shim can't tie to a repo fails, instead of quietly using your personal account.

## Broker reference

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
```

### TLS modes

| Mode | What happens | Client setup |
|---|---|---|
| `self` (default) | On first start, generates a 10-year ECDSA certificate and keeps it in the database, so the fingerprint stays the same across restarts. If you pass `-tls-hosts` with names the current certificate doesn't cover, a new certificate is generated. | `--fingerprint <SHA-256>` pins that exact certificate. |
| `files` | Uses your certificate and key (from an internal CA, `tailscale cert`, Let's Encrypt and so on). SIGHUP reloads them. | Nothing extra for a public CA. For an internal CA, use `--ca-file ca.pem`. |
| `off` | Plain HTTP. The broker logs a warning when it's on a non-loopback address. | `--insecure-http`, required for any non-loopback `http://` URL. |

Clients never turn verification off. With `--fingerprint`, the certificate has to match the pinned hash exactly, which is stricter than validating against a CA. If you run `setup` against an untrusted certificate, it prints that certificate's fingerprint so you can compare it and pin it.

### Admin UI

| Page | What's there |
|---|---|
| Dashboard | Counts for the last 24 hours, **active tokens** (client, repo, App, permissions, expiry, reuse count, **Revoke**), recent requests. |
| Clients | Create or disable/delete clients, IP allowlists, secrets (generate/rotate/remove), grants (ordered; first match wins), per-client tokens and history. |
| Apps | Add or replace Apps (paste or upload a `.pem`), test them against GitHub, delete Apps that no grant uses. |
| History | Every token request, denial, error, revocation and invalidation, filterable by client, event and repo. |
| Settings | Server settings (read-only), TLS fingerprint, the client setup command, password change. |

The UI requires the admin password. Sessions last 12 hours and are stored in SQLite. Forms carry CSRF tokens, cookies are `SameSite=Strict`, and a strict CSP is set. The session cookie is `Secure` when the broker serves TLS, or when a trusted proxy (`-trusted-proxies`) sends `X-Forwarded-Proto: https`. Failed logins are limited per source address (IPv6: per /64), separately from API authentication failures. To keep the UI away from agents, put it on its own port, for example `-ui-listen 127.0.0.1:8444`, and reach it through an SSH tunnel, or firewall that port.

### HTTP API

| Method / path | Auth | |
|---|---|---|
| `GET /healthz` | none | `ok` |
| `POST /v1/token` | `Bearer <secret>` | `{"repository":"owner/repo","permissions":{…}?}` → token, expiry, App, permissions, bot name and email |
| `POST /v1/invalidate` | Bearer | `{"token":"ghs_…"}`. GitHub rejected this token, so don't serve it from cache again (sent by `git credential reject`). |
| `GET /v1/whoami` | Bearer | client name, the IP the broker sees, grants |

Error codes: `400` bad body or repo name. `401` unknown or disabled secret. `403` no grant, permission escalation, wrong source IP, or the App isn't installed on that repo. `429` rate limited (60 tokens per minute per client; about 20 failed authentications per minute per IP, or per /64 for IPv6; a limited address is refused even with a valid secret). `502` GitHub error.

The broker reuses a token while it has more than 10 minutes left. Installation IDs are cached per owner for an hour, and bot identities are cached too. A failed identity lookup is retried at most every 5 minutes and never fails the token request.

## Extension reference

| Command | |
|---|---|
| `setup --broker URL [--fingerprint FP] [--ca-file F] [--insecure-http] [--host H]` | Reads the secret from stdin (no echo on a TTY), checks it against `/v1/whoami`, and saves `~/.config/gh-appauth/config.json` with mode 0600. |
| `status` | Broker reachability and latency, TLS details, client, grants, and for the current repo the App, bot, expiry, permissions and token source (never the token itself). |
| `token [OWNER/REPO] [--perm k=v]... [--json]` | Prints a token. The default repo is the current folder's `origin`. |
| `git-setup` | Sets up the credential helper for `https://github.com` and clears inherited helpers. Warns about SSH remotes. |
| `identity` | Sets repo-local `user.name` and `user.email` to the App bot. |
| `shim DIR` / `gh-shim` | Wrapper that gives plain `gh` an App token for `-R`/`--repo`, `$GH_APPAUTH_REPO`, or the current `origin`. |
| `exec [--repo R] -- CMD…` | Runs CMD with `GH_TOKEN` and `GITHUB_TOKEN` set. |
| `cache clear` | Deletes locally cached tokens. |

The environment variables `GH_APPAUTH_BROKER`, `GH_APPAUTH_SECRET`, `GH_APPAUTH_CA_FILE`, `GH_APPAUTH_FINGERPRINT` and `GH_APPAUTH_INSECURE_HTTP=1` override the config file, which is useful in containers.

**Local token cache.** Tokens are cached under `$XDG_RUNTIME_DIR/gh-appauth`, or `~/.cache/gh-appauth` if that isn't set. The directory is 0700 and the files are 0600, one per client secret, repo and permission set. A cached token is reused while it has more than 10 minutes left. If the broker is **unreachable** or rate limiting (429), a cached token with more than 1 minute left is used and a warning is printed. If the broker **refuses** (401/403), the cache entry is deleted and nothing falls back, so revocation takes effect right away.

**Known gaps**
- `gh repo clone owner/x` run outside a repo gets no token. Use `git clone https://github.com/owner/x` instead.
- `gh auth status` (which T3 Code shows) may report "not logged in" even though `gh pr …` and `git push` work. It inspects stored logins, not `GH_TOKEN` for a repo.
- SSH remotes never call the credential helper. `git-setup` warns about them.
- On Windows the `gh` shim isn't available (it is a shell script); use `gh appauth exec -- gh …`. The config file's permissions aren't checked there.

## Operations runbook

| Task | Steps |
|---|---|
| Add a client | UI → Clients → New client. Give the secret to the agent machine and run `gh appauth setup`. |
| Rotate a secret | Client page → *Generate new secret*. Re-run `setup` on the client, then remove the old secret. Both work in the meantime. |
| Revoke a client | Client page → Disabled, or *Delete client*. It gets 401 immediately and its live tokens are revoked at GitHub. |
| Change a grant | Client page → edit or remove the grant. Live tokens the new grants no longer cover are revoked at GitHub. |
| Revoke one token | Dashboard → *Revoke*. |
| Rotate an App key | Generate a new key in GitHub, then Apps → save it under the same name. Delete the old key in GitHub. |
| Reload | UI changes apply immediately. `systemctl reload gh-appauth-broker` (SIGHUP) re-reads the database and TLS certificate files; an invalid state is rejected and the broker keeps running on the old one. |
| Logs | `journalctl -u gh-appauth-broker`. Audit lines are JSON: `{"ts","event","status","client","ip","repo","app","perms","cached","reason"}`. Tokens and secrets are never logged. |
| Backup | `sqlite3 broker.db ".backup broker.bak"`, or copy the database while the broker is stopped. The file contains private keys, so store backups accordingly. |

## Development

```bash
go vet ./... && gofmt -l . && go test -race ./...
scripts/e2e.sh        # builds everything; fake GitHub; TLS files/self/off; real git + gh shim
```

The broker's only third-party dependency is `modernc.org/sqlite`, a pure-Go SQLite with no cgo, so cross-compiling stays easy. The extension uses the standard library only.

Layout:

```
main.go config.go broker.go git.go shim.go   the gh extension (root package)
internal/repo        owner/repo parsing shared by both binaries
internal/api         JSON types shared by both binaries
internal/fakegithub  fake GitHub API (verifies RS256 App JWTs) for tests and e2e
cmd/gh-appauth-broker/
  main.go            CLI, listeners, signals
  store.go           SQLite schema and queries
  config.go          validation, config snapshot
  github.go          App JWT, installation lookup, minting, identity, revocation
  server.go          API: auth, rate limits, grants, narrowing, cache, audit
  tlsconf.go         TLS modes, self-signed certificate
  ui.go, ui/         admin UI (embedded templates and assets)
deploy/              systemd unit, Caddyfile
scripts/e2e.sh       end-to-end test
```
