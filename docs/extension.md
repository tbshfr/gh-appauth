# Extension reference

The `gh-appauth` binary is a `gh` CLI extension, so its commands run as `gh appauth …`.

## Commands

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

## Environment variables

`GH_APPAUTH_BROKER`, `GH_APPAUTH_SECRET`, `GH_APPAUTH_CA_FILE`, `GH_APPAUTH_FINGERPRINT` and `GH_APPAUTH_INSECURE_HTTP=1` override the config file, which is useful in containers. `GH_APPAUTH_REPO` tells the `gh` shim which repo to use when it can't work it out from the command or the current folder.

## Local token cache

Tokens are cached under `$XDG_RUNTIME_DIR/gh-appauth`, or `~/.cache/gh-appauth` if that isn't set. The directory is 0700 and the files are 0600, one per client secret, repo and permission set.

A cached token is reused while it has more than 10 minutes left. If the broker is unreachable or rate limiting (429), a cached token with more than 1 minute left is used and a warning is printed. If the broker refuses (401 or 403), the cache entry is deleted and nothing falls back, so revocation takes effect right away.

## Known gaps

- `gh repo clone owner/x` run outside a repo gets no token. Use `git clone https://github.com/owner/x` instead.
- `gh auth status` (which T3 Code shows) may report "not logged in" even though `gh pr …` and `git push` work. It inspects stored logins, not `GH_TOKEN` for a repo.
- SSH remotes never call the credential helper. `git-setup` warns about them.
- On Windows the `gh` shim isn't available because it is a shell script. Use `gh appauth exec -- gh …` instead. The config file's permissions aren't checked there.
