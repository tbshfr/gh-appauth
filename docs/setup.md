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
- Under repository permissions, set Contents, Pull requests and Issues to read & write, and Metadata to read. Add Workflows only if agents need to edit `.github/workflows`.
- Install the App on selected repositories.
- Generate a private key (`.pem`) and note the App ID.

The App's permissions are the upper limit for every token the broker issues for it. Grants can only narrow them further.

You can create more than one App, for example one per group of repos, and add them all to the same broker.

## 3. Admin UI

The example unit serves the admin UI on its own port, bound to loopback (`-ui-listen 127.0.0.1:8444`), so agents that can reach the API port can't reach the login page. If the broker runs on another machine, either reach the UI through an SSH tunnel, or change that flag to `-ui-listen 0.0.0.0:8444` in the unit and firewall the port so only your workstation can reach it.

Open `https://BROKER:8444/ui/` (or `https://localhost:8444/ui/` on the broker host) and sign in. With a self-signed certificate the browser shows a warning; you can check the fingerprint against the one from step 1. Then:

1. On the Apps page, add the App with a name, its App ID and the `.pem` file. Click Test to confirm GitHub accepts the key.
2. On the Clients page, create one client per agent or machine. The secret is shown only once, so copy it now.
3. On the client's page, add grants. Each grant has one or more repo globs (`acme/api-*`), an App, and optional maximum permissions. If you set no permissions, tokens get everything the App installation has. Grants are checked in order and the first one whose pattern matches wins.

If you want to tie the client to the machine it runs on, fill in its allowed source IPs or CIDRs in the client's settings.

## 4. Agent machine

```bash
gh extension install tbshfr/gh-appauth           # or: go build && gh extension install .
gh appauth setup --broker https://broker.lan:8443 --fingerprint AB:CD:…   # paste the secret
gh appauth git-setup                              # git uses the broker for https://github.com
gh appauth shim ~/.local/gh-appauth-bin           # optional: plain `gh` uses App tokens
echo 'export PATH="$HOME/.local/gh-appauth-bin:$PATH"' >> ~/.bashrc   # see below
gh appauth status
```

The shim only takes effect where its folder comes before the real `gh` in `PATH`. Exporting `PATH` in your current shell lasts until that shell exits, so put it in the agent user's shell profile (`~/.bashrc`, `~/.zshrc`, or the environment of the service that starts the agent), then open a new shell. `type -a gh` should list the shim's folder first.

`setup` reads the secret from stdin, checks it against the broker, and prints the grants it found. If the broker's certificate isn't trusted yet, `setup` prints its fingerprint so you can compare it with the one from step 1.

After this, `git clone/fetch/push https://github.com/acme/api-core` and `gh pr create` work unchanged. To make commits show up as the App's bot, run `gh appauth identity` in the repo. It applies to all of the repo's worktrees.

The agent's OS user must have no `gh auth login` session. Then any `gh` call the shim can't tie to a repo fails, instead of quietly using your personal account.

Remotes must use HTTPS. SSH remotes never call the credential helper, and `git-setup` warns when it finds one. See [Known gaps](extension.md#known-gaps) for the other cases that need a workaround, including Windows.

In containers you can skip the config file and set `GH_APPAUTH_BROKER`, `GH_APPAUTH_SECRET` and the trust settings as [environment variables](extension.md#environment-variables).
