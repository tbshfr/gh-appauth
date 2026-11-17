# Setup

Setup has four parts: the broker host, a GitHub App, the admin UI, and each agent machine. Read [security.md](security.md) first if you haven't decided where the broker should run.

## 1. Broker host

```bash
go build -o gh-appauth-broker ./cmd/gh-appauth-broker   # or use a release binary
sudo install -m 0755 gh-appauth-broker /usr/local/bin/
sudo gh-appauth-broker set-password -data-dir /var/lib/gh-appauth-broker
sudo cp deploy/gh-appauth-broker.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now gh-appauth-broker
journalctl -u gh-appauth-broker | grep fingerprint     # note the TLS fingerprint
```

By default the broker keeps its database in a `data/` directory next to its binary (created with mode 0700). Use `-data-dir DIR` or `GH_APPAUTH_BROKER_DATA_DIR` to put it somewhere else.

The example unit runs under `DynamicUser=`, which can't write next to the binary, so it uses `-data-dir /var/lib/gh-appauth-broker` (its `StateDirectory=`). On first start systemd moves that directory to `/var/lib/private/` and gives it to the dynamic user, which is why `set-password` runs before the service is enabled. You can change the password later on the Settings page.

Keep the clock in sync with chrony or systemd-timesyncd. GitHub rejects App JWTs from a clock that's more than about a minute off.

By default the broker serves TLS with a self-signed certificate and clients pin its fingerprint. To use your own certificate or put the broker behind a reverse proxy, see [TLS modes](broker.md#tls-modes) and [Running behind a reverse proxy](operations.md#running-behind-a-reverse-proxy).

## 2. Create a GitHub App

In GitHub, go to Settings → Developer settings → GitHub Apps → New GitHub App:

- Turn off the webhook.
- Under repository permissions, pick what your agents need.
- Install the App on selected repositories.
- Generate a private key (`.pem`) and note the App ID.

These are the repository permissions agents most commonly need. Leave out any you don't want them to have.

| Permission | Access | What it's for |
|---|---|---|
| Metadata | Read-only | GitHub sets this one on every App. |
| Contents | Read and write | `git clone`, `fetch` and `push` |
| Pull requests | Read and write | `gh pr create`, `view`, `comment` and `merge` |
| Issues | Read and write | `gh issue` |
| Actions | Read-only | `gh run list`, `gh run view` and job logs |
| Checks | Read-only | CI results in `gh pr checks` and `gh pr view` |
| Commit statuses | Read-only | CI results from services that report commit statuses instead of check runs |
| Workflows | Read and write | Pushing changes to `.github/workflows` |

On a public repo anyone can read check results, so `gh pr checks` works without Checks or Commit statuses. On a private repo it fails with `Resource not accessible by integration`.

The App's permissions are the upper limit for every token the broker issues for it. Grants can only narrow them further. If you add a permission to an App that's already installed, GitHub asks the owner of each installation to approve it. Until they do, the broker's tokens don't include it.

You can create more than one App, for example one per group of repos, and add them all to the same broker.

## 3. Admin UI

The example unit serves the admin UI on its own port, bound to loopback (`-ui-listen 127.0.0.1:8444`), so agents that can reach the API port can't reach the login page. If the broker runs on another machine, either reach the UI through an SSH tunnel, or change that flag to `-ui-listen 0.0.0.0:8444` in the unit and firewall the port so only your workstation can reach it.

Open `https://BROKER:8444/ui/` (or `https://localhost:8444/ui/` on the broker host) and sign in. With a self-signed certificate the browser shows a warning; you can check the fingerprint against the one from step 1. Then:

1. On the Apps page, add the App with a name, its App ID and the `.pem` file. Click Test to confirm GitHub accepts the key.
2. On the Clients page, create one client per agent or machine. The secret is shown only once, so copy it now.
3. On the client's page, add grants. Each grant has one or more repo globs (`acme/api-*`), an App, and optional maximum permissions. If you set no permissions, tokens get everything the App installation has. Grants are checked in order and the first one whose pattern matches wins.

If you want to tie the client to the machine it runs on, fill in its allowed source IPs or CIDRs in the client's settings.

## 4. Agent machine

Run these as the OS user the agent runs as.

1. Install the extension:

   ```bash
   gh extension install tbshfr/gh-appauth   # or: go build -o gh-appauth ./cmd/gh-appauth && gh extension install .
   ```

2. Connect it to the broker. Right after you create a client or click Generate secret, the client's page shows the secret with the `setup` command above it. If you've left the page since, generate a new secret to get both again.

   Above the command you can change the broker URL to the one this machine uses, turn off the [local token cache](extension.md#without-the-local-cache), and under Advanced set a GitHub Enterprise Server host or a CA file. The UI adds `--fingerprint` and `--insecure-http` when the broker's TLS mode and URL need them. Written by hand, the command looks like this:

   ```bash
   gh appauth setup --broker https://broker.lan:8443 --fingerprint AB:CD:…
   ```

   Paste the secret when it asks. It reads the secret from stdin, so you can also pipe it in. `setup` checks the secret with the broker and prints the client's grants. If the broker's certificate isn't trusted yet, it prints the fingerprint so you can compare it with the one from step 1.

3. Point git at the broker for `https://github.com`:

   ```bash
   gh appauth git-setup
   ```

   Remotes must use HTTPS, because SSH remotes never call the credential helper. `git-setup` warns when it finds one.

4. Optionally, make plain `gh` use App tokens:

   ```bash
   gh appauth shim ~/.local/gh-appauth-bin
   echo 'export PATH="$HOME/.local/gh-appauth-bin:$PATH"' >> ~/.bashrc   # zsh: ~/.zshrc
   source ~/.bashrc                                                    # zsh: source ~/.zshrc
   ```

   `type -a gh` should list the shim's folder first. If a service starts the agent, add the folder to the front of `PATH` in that service's environment instead.

   The agent's OS user must have no `gh auth login` session. Then a `gh` call the shim can't tie to a repo fails instead of quietly using your personal account.

5. Check the result with `gh appauth status`.

From then on, `git clone`, `fetch` and `push` over HTTPS and `gh pr create` work unchanged. Commits show up as the App's bot in repos that don't set their own `user.name` and `user.email`; [Commit identity](extension.md#commit-identity) explains when that happens and how to turn it off. [Known gaps](extension.md#known-gaps) lists the cases that need a workaround, including Windows.

To update the extension, run `gh extension install --force tbshfr/gh-appauth`, which upgrades an installed extension. `gh extension upgrade appauth` won't work, because it refuses to run without a `gh auth login` session and stops with "To get started with GitHub CLI, please run: gh auth login".

In containers you can skip the config file and set `GH_APPAUTH_BROKER`, `GH_APPAUTH_SECRET` and the trust settings as [environment variables](extension.md#environment-variables).
