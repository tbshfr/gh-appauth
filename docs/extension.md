# Extension reference

The `gh-appauth` binary is a `gh` CLI extension, so its commands run as `gh appauth …`.

## Commands

| Command | |
|---|---|
| `setup --broker URL [--fingerprint FP] [--ca-file F] [--insecure-http] [--host H]` | Reads the secret from stdin (no echo on a TTY), checks it against `/v1/whoami`, and saves `~/.config/gh-appauth/config.json` with mode 0600. |
| `status` | Broker reachability and latency, TLS details, client, grants, and for the current repo the App, bot, expiry, permissions and token source (never the token itself). |
| `token [OWNER/REPO] [--perm k=v]... [--json]` | Prints a token. The default repo is the current folder's `origin`. |
| `repos OWNER [--no-archived] [--json]` | Lists OWNER's repos this client can get a token for, one per line with tab-separated name, default branch, visibility and App. Use it in place of `gh repo list OWNER`, which can't see past a single repo. |
| `git-setup` | Sets up the credential helper for `https://github.com`, clears inherited helpers, and registers a `post-checkout` hook for the [automatic bot identity](#commit-identity) and a `prepare-commit-msg` hook for the optional [co-author trailer](#crediting-yourself-as-co-author). Warns about SSH remotes. |
| `identity` | Sets repo-local `user.name` and `user.email` to the App bot. Usually not needed, see [Commit identity](#commit-identity). |
| `shim DIR` / `gh-shim` | Wrapper that gives plain `gh` an App token for the repo the command targets. See [Which repo the shim picks](#which-repo-the-shim-picks). |
| `exec [--repo R] -- CMD…` | Runs CMD with `GH_TOKEN` and `GITHUB_TOKEN` set. Without `--repo` it uses `$GH_REPO`, then `$GH_APPAUTH_REPO`, then the remote gh would use in the current folder. |
| `cache clear` | Deletes locally cached tokens. |
| `version` | Prints the extension version. |

## Environment variables

`GH_APPAUTH_BROKER`, `GH_APPAUTH_SECRET`, `GH_APPAUTH_CA_FILE`, `GH_APPAUTH_FINGERPRINT` and `GH_APPAUTH_INSECURE_HTTP=1` override the config file, which is useful in containers. `GH_APPAUTH_GITHUB_API` sets the GitHub API URL the shim uses to check a token (see [Local token cache](#local-token-cache)). `GH_APPAUTH_REPO` tells the `gh` shim and `exec` which repo to use when the command doesn't name one and `GH_REPO` isn't set. It takes priority over the current folder's remotes.

## Commit identity

Commits show up as the App's bot when the repo's own config (`.git/config`) sets `user.name` and `user.email` to the bot. gh-appauth sets them on its own the first time it gets a token for a repo whose config sets neither. A global identity in `~/.gitconfig` doesn't count, so a repo where you set your own identity keeps it. This happens:

- when `git clone`, `fetch`, `pull` or `push` asks the credential helper for the repo in `origin`,
- when the `gh` shim gets a token for the repo in `origin`,
- after a clone or `git worktree add`, through the `post-checkout` hook that `git-setup` registers in the global git config. A public repo's clone never asks for credentials, so without the hook the identity would only be set at the first push, after the first commits. Hooks defined in git config need git 2.54 or later; older versions ignore the setting, and you can run `gh appauth identity` after the clone instead. The hook runs next to the repo's own hooks and doesn't replace them.

A line on stderr says when the identity was set. To turn this off, run `git config --global gh-appauth.autoIdentity false`, or set it in a single repo without `--global`.

When you clone a public repo the client has no grant for, the hook's token request is refused. The broker records it in the request history, and nothing else happens.

### Crediting yourself as co-author

To add yourself as co-author on the bot's commits:

```sh
git config --global gh-appauth.coAuthor "Your Name <ID+login@users.noreply.github.com>"
```

Use an email that is verified on your GitHub account, such as the noreply address shown under Settings -> Emails. Only commits authored by a GitHub App bot (`…[bot]@users.noreply.…`) get the `Co-authored-by` trailer, so your own commits stay as they are. The setting is off by default. To turn it off in one repo, run `git config gh-appauth.coAuthor ""` there.

The trailer is added by a `prepare-commit-msg` hook that `git-setup` registers, so it also works with `--no-verify`. If you ran `git-setup` before this feature existed, run it again. Only commits made without the editor get the trailer: `git commit -m`, `-F`, `--amend --no-edit` (which doesn't add a second one) and merges with `--no-edit`. For a message you write in the editor, add the trailer yourself. Commits that `git rebase` or `git cherry-pick` replay without a conflict keep their message. Like the `post-checkout` hook, this needs git 2.54 or later.

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

A cached token is reused while it has more than 10 minutes left. If the broker is unreachable or rate limiting (429), a cached token with more than 1 minute left is used and a warning is printed. If the broker refuses (401 or 403), the cache entry is deleted and nothing falls back, so revoking a client takes effect right away.

A token can also stop working before it expires, for example when you revoke it on the dashboard, narrow a grant or replace an App. The cache can't know that, so gh-appauth notices when a command fails because of it, and drops just that token:

- **gh shim, for an agent.** When neither stdout nor stderr is a terminal, the shim reads gh's output. If gh fails with GitHub's `HTTP 401: Bad credentials`, the shim checks with GitHub that the message is about this token: it could also be about another credential, or quoted in what gh printed. If GitHub refuses the token, or doesn't answer within 3 seconds, the shim drops the token locally and at the broker, gets a new one and runs the command once more. It holds the failed run's output back and discards it, so the agent sees only the second run plus one line: `gh-appauth: GitHub rejected the token for OWNER/REPO (revoked?); got a new one and ran the command again`.
- **gh shim, at a terminal.** gh writes straight to the terminal, as without the shim. When gh fails with exit code 1, the shim asks GitHub whether it still takes the token, waiting at most 3 seconds. If GitHub refuses it, the shim drops it the same way and runs the command once more, after the error you already saw.
- **git.** git tells the credential helper when GitHub rejects a credential, and the helper drops that token. git doesn't retry, so that command fails, and the next one gets a new token.

The shim runs a command again only if gh failed within 10 seconds, since a later failure may come after the command already changed something. The second run gets the same stdin: a file is read again from where gh started, and a pipe is kept for it when the arguments tell gh to read stdin (`--body-file -`, `--input -`, `-F body=@-`). Any other pipe is left untouched for whoever reads it next, as in `... | while read n; do gh pr view "$n"; done`, so then the shim only drops the token and asks you to run the command again. The same goes for a failure after 10 seconds: the next command gets a new token.

While gh runs, the shim passes SIGINT, SIGTERM and SIGHUP on to it, so a timeout that stops the shim stops gh too. On Linux gh also gets SIGTERM if the shim is killed with SIGKILL. At a terminal, Ctrl-C and a hangup already reach gh from the terminal, so the shim doesn't send them a second time, and gh's own result decides how the shim exits. When gh dies of one of these three signals, or the shim passed one on, the shim dies of it too, so a shell loop around it ends as it would for gh. Other signals that stop gh, such as SIGPIPE from `| head`, give exit code 128 plus the signal number. Signals the shim started with ignored, as under `nohup`, stay ignored.

To check a token, the shim calls `https://api.github.com`, `https://api.HOST` for a GHE.com host, or `https://HOST/api/v3` for GitHub Enterprise Server. Set `GH_APPAUTH_GITHUB_API` if the API is somewhere else.

## Known gaps

- `gh repo clone` needs `OWNER/REPO` or a URL. A bare name like `gh repo clone x` refers to the logged-in user's repo, and an App token has no user. When you clone a fork, gh also fetches the parent into an `upstream` remote using the fork's token, so a private parent fails unless you pass `--no-upstream`.
- A token covers one repo, so commands that touch two repos can fail: `gh pr create` from a branch in a fork, `gh issue transfer`, or `gh pr checkout` of a PR whose branch is in a private fork.
- `gh repo create` and commands that work at user or org level (`gh gist`, `gh project`, `gh org`, `--org` secrets and variables) can't get a token for a single repo. `gh repo fork` gets the source repo's token, and creating the fork usually fails with it. The token only covers the source repo, and without `--org` gh forks into the logged-in user's account, which an App token doesn't have. With `--clone`, gh clones the new fork using the same token, which fails if the fork is private. Run inside a repo, `gh repo list OWNER` and `gh search` get that repo's token, so they only see what that token can reach. `gh appauth repos OWNER` lists every repo the client can get a token for.
- The shim doesn't read the repo from `gh api repos/OWNER/REPO/…` paths, or from `gh repo edit|archive|unarchive|delete|sync OWNER/REPO`. Neither accepts `-R`, so set `GH_REPO=OWNER/REPO` for the command. `gh api` paths that use `{owner}/{repo}` work.
- `gh auth status` (which T3 Code shows) may report "not logged in" even though `gh pr …` and `git push` work. It inspects stored logins, not `GH_TOKEN` for a repo. Scripts that check it before doing anything need to accept `gh appauth status` or `gh appauth repos OWNER` succeeding instead.
- Without a `gh auth login` session, `gh extension upgrade appauth` refuses to run and asks you to log in. Use `gh extension install --force tbshfr/gh-appauth` instead, which upgrades the installed extension. See [Setup](setup.md#4-agent-machine).
- SSH remotes never call the credential helper. `git-setup` warns about them.
- On Windows the `gh` shim isn't available because it is a shell script. Use `gh appauth exec -- gh …` instead. The config file's permissions aren't checked there.
