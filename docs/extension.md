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
| `shim DIR` / `gh-shim` | Wrapper that gives plain `gh` an App token for the repo the command targets. See [Which repo the shim picks](#which-repo-the-shim-picks). |
| `exec [--repo R] -- CMD…` | Runs CMD with `GH_TOKEN` and `GITHUB_TOKEN` set. Without `--repo` it uses `$GH_REPO`, then `$GH_APPAUTH_REPO`, then the remote gh would use in the current folder. |
| `cache clear` | Deletes locally cached tokens. |
| `version` | Prints the extension version. |

## Environment variables

`GH_APPAUTH_BROKER`, `GH_APPAUTH_SECRET`, `GH_APPAUTH_CA_FILE`, `GH_APPAUTH_FINGERPRINT` and `GH_APPAUTH_INSECURE_HTTP=1` override the config file, which is useful in containers. `GH_APPAUTH_REPO` tells the `gh` shim and `exec` which repo to use when the command doesn't name one and `GH_REPO` isn't set. It takes priority over the current folder's remotes.

## Which repo the shim picks

The shim follows the same order gh does, so the token matches the repo gh is about to work on. The first match wins:

1. The repository argument of `gh repo clone`, `gh repo view`, `gh repo fork` and `gh repo set-default`, or a PR or issue URL passed to a `gh pr …` or `gh issue …` command, such as `gh pr view https://github.com/acme/web/pull/7`. `gh co` counts as `gh pr checkout`.
2. `-R`/`--repo`.
3. `$GH_REPO`, then `$GH_APPAUTH_REPO`.
4. The current folder's remotes, picked the way gh does: a remote chosen with `gh repo set-default` wins. Otherwise the shim takes the first remote on the GitHub host, preferring `upstream`, then `github`, then `origin`.

If none of these match, gh runs without a token.

In a clone of a fork, `gh pr …` therefore works on the parent in `upstream`, while `git push` goes to the fork in `origin`. The client needs grants for both. Run `gh repo set-default` if you want gh to work on the fork instead.

## Local token cache

Tokens are cached under `$XDG_RUNTIME_DIR/gh-appauth`, or `~/.cache/gh-appauth` if that isn't set. The directory is 0700 and the files are 0600, one per client secret, repo and permission set.

A cached token is reused while it has more than 10 minutes left. If the broker is unreachable or rate limiting (429), a cached token with more than 1 minute left is used and a warning is printed. If the broker refuses (401 or 403), the cache entry is deleted and nothing falls back, so revocation takes effect right away.

## Known gaps

- `gh repo clone` needs `OWNER/REPO` or a URL. A bare name like `gh repo clone x` refers to the logged-in user's repo, and an App token has no user. When you clone a fork, gh also fetches the parent into an `upstream` remote using the fork's token, so a private parent fails unless you pass `--no-upstream`.
- A token covers one repo, so commands that touch two repos can fail: `gh pr create` from a branch in a fork, `gh issue transfer`, or `gh pr checkout` of a PR whose branch is in a private fork.
- `gh repo create` and commands that work at user or org level (`gh gist`, `gh project`, `gh org`, `--org` secrets and variables) can't get a token for a single repo. `gh repo fork` gets the source repo's token, and creating the fork usually fails with it. The token only covers the source repo, and without `--org` gh forks into the logged-in user's account, which an App token doesn't have. With `--clone`, gh clones the new fork using the same token, which fails if the fork is private. Run inside a repo, `gh repo list OWNER` and `gh search` get that repo's token, so they only see what that token can reach.
- The shim doesn't read the repo from `gh api repos/OWNER/REPO/…` paths, or from `gh repo edit|archive|unarchive|delete|sync OWNER/REPO`. Neither accepts `-R`, so set `GH_REPO=OWNER/REPO` for the command. `gh api` paths that use `{owner}/{repo}` work.
- `gh auth status` (which T3 Code shows) may report "not logged in" even though `gh pr …` and `git push` work. It inspects stored logins, not `GH_TOKEN` for a repo.
- SSH remotes never call the credential helper. `git-setup` warns about them.
- On Windows the `gh` shim isn't available because it is a shell script. Use `gh appauth exec -- gh …` instead. The config file's permissions aren't checked there.
