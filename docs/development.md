# Development

```bash
go vet ./... && gofmt -l . && go test -race ./...
scripts/e2e.sh        # builds everything; fake GitHub; TLS files/self/off; real git + gh shim
```

To work on the admin UI, `scripts/dev.sh` runs the broker against the fake GitHub with seeded apps, clients, grants, tokens and denied requests, at http://127.0.0.1:8443/ui/ (password `dev-admin-password`). It rebuilds on every run and keeps its state in `.dev/`; `--reset` seeds it again from scratch, and `PORT` picks another port.

`scripts/e2e.sh` runs offline. It builds both binaries, starts a fake GitHub API that checks App JWT signatures, configures the broker through the admin UI, and drives real `git` and the `gh` shim against it in all three TLS modes. Set `KEEP=1` to keep its work directory afterwards.

The broker's third-party dependencies are `modernc.org/sqlite`, a pure-Go SQLite with no cgo, so cross-compiling stays easy, and `golang.org/x/oauth2` and `github.com/coreos/go-oidc/v3` for single sign-on. The extension uses the standard library only.

`scripts/release.sh [VERSION]` builds the release binaries into `dist/`.

## Layout

```
internal/repo        owner/repo parsing shared by both binaries
internal/api         JSON types shared by both binaries
internal/buildinfo   version stamp shared by both binaries
internal/fakegithub  fake GitHub API (verifies RS256 App JWTs) for tests and e2e
internal/fakeoidc    fake OIDC provider (checks client auth, codes, PKCE) for tests
cmd/gh-appauth/      gh extension
  main.go            CLI: setup, status, token, repos
  config.go          client config
  broker.go          broker client, token cache
  git.go             credential helper, git-setup, identity, hooks
  shim.go            gh shim, shim install, exec
  retry*.go          gh shim: retry with a new token, signals
  sysproc_*.go       gh shim: gh dies with the shim (Linux)
cmd/gh-appauth-broker/
  main.go            CLI, listeners, signals
  store.go           SQLite schema and queries
  config.go          validation, config snapshot
  github.go          App JWT, installation lookup, minting, identity, revocation
  server.go          API: auth, rate limits, grants, narrowing, cache, audit
  tlsconf.go         TLS modes, self-signed certificate
  ui.go, ui/         admin UI (embedded templates and assets)
  oidc.go            admin UI single sign-on: flags, discovery, callback, groups
deploy/              systemd unit, Caddyfile
scripts/dev.sh       broker with seeded data for UI work
scripts/e2e.sh       end-to-end test
scripts/release.sh   release binaries
testdata/fakegithub  fake GitHub server binary for e2e
docs/                user documentation
```
