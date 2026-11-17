# Development

```bash
go vet ./... && gofmt -l . && go test -race ./...
scripts/e2e.sh        # builds everything; fake GitHub; TLS files/self/off; real git + gh shim
```

`scripts/e2e.sh` runs offline. It builds both binaries, starts a fake GitHub API that checks App JWT signatures, configures the broker through the admin UI, and drives real `git` and the `gh` shim against it in all three TLS modes. Set `KEEP=1` to keep its work directory afterwards.

The broker's only third-party dependency is `modernc.org/sqlite`, a pure-Go SQLite with no cgo, so cross-compiling stays easy. The extension uses the standard library only.

`scripts/release.sh [VERSION]` builds the release binaries into `dist/`.

## Layout

```
internal/repo        owner/repo parsing shared by both binaries
internal/api         JSON types shared by both binaries
internal/buildinfo   version stamp shared by both binaries
internal/fakegithub  fake GitHub API (verifies RS256 App JWTs) for tests and e2e
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
deploy/              systemd unit, Caddyfile
scripts/e2e.sh       end-to-end test
scripts/release.sh   release binaries
testdata/fakegithub  fake GitHub server binary for e2e
docs/                user documentation
```
