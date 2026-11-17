# Setup

Setup has four parts: the broker host, a GitHub App, the admin UI, and each agent machine. Read [security.md](security.md) first if you haven't decided where the broker should run.

## 1. Broker host

On a Linux host with systemd, install the latest release and start it:

```bash
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
URL=https://github.com/tbshfr/gh-appauth/releases/latest/download
curl -fsSLO "$URL/gh-appauth-broker_linux_$ARCH" -O "$URL/checksums.txt"
sha256sum -c --ignore-missing checksums.txt
sudo install -m 0755 "gh-appauth-broker_linux_$ARCH" /usr/local/bin/gh-appauth-broker
sudo curl -fsSLo /etc/systemd/system/gh-appauth-broker.service "$URL/gh-appauth-broker.service"
sudo gh-appauth-broker set-password -data-dir /var/lib/gh-appauth-broker
sudo systemctl daemon-reload && sudo systemctl enable --now gh-appauth-broker
```

To build from source instead, run `go build ./cmd/gh-appauth-broker` and use the unit in `deploy/`. To update later, download and install the binary again and run `sudo systemctl restart gh-appauth-broker`.

`set-password` runs before the service starts because on first start systemd moves `/var/lib/gh-appauth-broker` to `/var/lib/private/` and hands it to the service's dynamic user. You can change the password later on the Settings page.

Agent machines connect to the broker on port 8443, so let them through the host's firewall.

The unit's `ExecStart` line sets the broker's flags, and the comments below it list the others you can add. You'll most likely want `-tls-hosts`, which adds the names and IPs clients use to the self-signed certificate (otherwise it only covers localhost and the hostname). Change them with `sudo systemctl edit --full gh-appauth-broker`, then run `sudo systemctl restart gh-appauth-broker`.

The broker serves TLS with a self-signed certificate, and clients pin its fingerprint. To use your own certificate or a reverse proxy, see [TLS modes](broker.md#tls-modes) and [Running behind a reverse proxy](operations.md#running-behind-a-reverse-proxy).

Keep the host's clock in sync. GitHub rejects App JWTs from a clock that's more than about a minute off.

## 2. Create a GitHub App

In GitHub, go to Settings → Developer settings → GitHub Apps → New GitHub App:

- GitHub requires a Homepage URL. Any URL works, for example `https://github.com/tbshfr/gh-appauth`.
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

Open `https://BROKER:8444/ui/` (or `https://localhost:8444/ui/` on the broker host) and sign in. With a self-signed certificate the browser shows a warning. To check it, compare the fingerprint the browser shows with the output of `sudo gh-appauth-broker fingerprint -data-dir /var/lib/gh-appauth-broker` on the broker host. Then:

1. On the Apps page, add the App with a name, its App ID and the `.pem` file. Click Test to confirm GitHub accepts the key.
2. On the Clients page, create one client per agent or machine. The client's page then shows its secret, with the setup command for [section 4](#4-agent-machine) above it. Above the command you can change the broker URL to the one the agent machine uses, turn off the [local token cache](extension.md#without-the-local-cache), and under Advanced set a GitHub Enterprise Server host or a CA file. The command and secret disappear when the page reloads, for example after you add a grant, so copy them now. If you lose them, generate a new secret.
3. On the client's page, add grants. Each grant has one or more repo globs (`acme/api-*`), an App, and optional maximum permissions. If you set no permissions, tokens get everything the App installation has. Grants are checked in order and the first one whose pattern matches wins.

If you want to tie the client to the machine it runs on, fill in its allowed source IPs or CIDRs in the client's settings.

## 4. Agent machine

Run these as the OS user the agent runs as. That user needs the [GitHub CLI](https://cli.github.com) installed, and must not have a `gh auth login` session; otherwise a `gh` call that gh-appauth can't tie to a repo quietly uses your personal account.

1. Install the extension:

   ```bash
   gh extension install tbshfr/gh-appauth   # or: go build -o gh-appauth ./cmd/gh-appauth && gh extension install .
   ```

2. Run the `setup` command you copied in [section 3](#3-admin-ui) and paste the secret when it asks. Written by hand, it looks like this:

   ```bash
   gh appauth setup --broker https://broker.lan:8443 --fingerprint AB:CD:…
   ```

   `setup` reads the secret from stdin, so you can also pipe it in. It checks the secret with the broker and prints the client's grants. If the broker's certificate isn't trusted, it prints the certificate's fingerprint so you can compare it with the one on the admin UI's Settings page.

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

5. Check the result with `gh appauth status`.

From then on, `git clone`, `fetch` and `push` over HTTPS and `gh pr create` work unchanged. [Commit identity](extension.md#commit-identity) explains when commits show up as the App's bot and how to turn that off. [Known gaps](extension.md#known-gaps) lists the cases that need a workaround, including Windows.

To update the extension, run `gh extension install --force tbshfr/gh-appauth`, which upgrades an installed extension. `gh extension upgrade appauth` won't work, because it refuses to run without a `gh auth login` session and stops with "To get started with GitHub CLI, please run: gh auth login".

In containers you can skip the config file and set `GH_APPAUTH_BROKER`, `GH_APPAUTH_SECRET` and the trust settings as [environment variables](extension.md#environment-variables).
