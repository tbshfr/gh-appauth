#!/usr/bin/env bash
# End-to-end test: real binaries, a fake GitHub, real git.
# Runs offline. Usage: scripts/e2e.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [[ "${KEEP:-}" == 1 ]]; then echo "work dir kept: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

pass() { printf '  \033[32mok\033[0m   %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; echo "--- broker log"; cat "$WORK/broker.log" 2>/dev/null || true; exit 1; }

echo "== build"
BIN=$WORK/bin
mkdir -p "$BIN"
(cd "$ROOT" && go build -o "$BIN/gh-appauth" . \
  && go build -o "$BIN/gh-appauth-broker" ./cmd/gh-appauth-broker \
  && go build -o "$BIN/fakegithub" ./testdata/fakegithub)
EXT=$BIN/gh-appauth
BROKER=$BIN/gh-appauth-broker

echo "== keys and certificates"
openssl genrsa -traditional -out "$WORK/app1.pem" 2048 2>/dev/null   # PKCS#1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK/app2.pem" 2>/dev/null  # PKCS#8
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=e2e test CA" \
  -keyout "$WORK/ca.key" -out "$WORK/ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=127.0.0.1" -keyout "$WORK/tls.key" -out "$WORK/tls.csr" 2>/dev/null
printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n' > "$WORK/ext.cnf"
openssl x509 -req -in "$WORK/tls.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" -CAcreateserial \
  -days 1 -extfile "$WORK/ext.cnf" -out "$WORK/tls.crt" 2>/dev/null

echo "== fake GitHub"
cat > "$WORK/fakegh.json" <<EOF
{"apps": [
  {"id": 1001, "slug": "backend-bot", "bot_id": 555, "private_key_file": "$WORK/app1.pem",
   "installations": [{"id": 11, "owner": "acme", "repos": ["api-core", "api-auth"],
     "permissions": {"contents": "write", "pull_requests": "write", "metadata": "read"}}]},
  {"id": 1002, "slug": "frontend-bot", "bot_id": 777, "private_key_file": "$WORK/app2.pem",
   "installations": [{"id": 22, "owner": "acme", "repos": ["web", "site"], "permissions": {"contents": "write", "metadata": "read"}}]}
]}
EOF
"$BIN/fakegithub" -config "$WORK/fakegh.json" -addr-file "$WORK/fakegh.addr" 2>"$WORK/fakegh.log" &
PIDS+=($!)
for _ in $(seq 50); do [[ -s "$WORK/fakegh.addr" ]] && break; sleep 0.1; done
GHAPI="http://$(cat "$WORK/fakegh.addr")"

DB=$WORK/broker.db
{ printf 'e2e-admin-password\n' | "$BROKER" set-password -db "$DB" 2>/dev/null; } || fail "set-password"; pass "set-password"

# Admin UI helpers. UI_CURL holds per-phase curl options (e.g. --cacert).
UI_CURL=()
ui_login() { # $1 = UI base URL
  UI_BASE=$1
  rm -f "$WORK/jar"
  curl -sS "${UI_CURL[@]}" -c "$WORK/jar" -o /dev/null -d password=e2e-admin-password "$UI_BASE/ui/login"
  CSRF=$(curl -sS "${UI_CURL[@]}" -b "$WORK/jar" "$UI_BASE/ui/" | sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' | head -1)
  [[ -n "$CSRF" ]] || fail "admin UI login"
}
ui_post() { # $1 = path, rest = curl -F fields; prints the page after the redirect
  local path=$1; shift
  curl -sS -L "${UI_CURL[@]}" -b "$WORK/jar" -c "$WORK/jar" -F "csrf=$CSRF" "$@" "$UI_BASE$path"
}

BROKER_PID=
start_broker() { # args: extra flags
  : > "$WORK/broker.log"
  "$BROKER" serve -db "$DB" -listen 127.0.0.1:0 -github-api "$GHAPI" "$@" >"$WORK/audit.log" 2>"$WORK/broker.log" &
  BROKER_PID=$!
  PIDS+=("$BROKER_PID")
  for _ in $(seq 100); do
    if grep -q "API listening on" "$WORK/broker.log"; then break; fi
    sleep 0.1
  done
  BROKER_URL=$(sed -n 's/.*API listening on \([^ ]*\).*/\1/p' "$WORK/broker.log" | head -1)
  [[ -n "$BROKER_URL" ]] || fail "broker did not start"
}
stop_broker() { kill "$BROKER_PID"; wait "$BROKER_PID" 2>/dev/null || true; }

# Isolated client environment.
export HOME=$WORK/home XDG_CONFIG_HOME=$WORK/home/.config XDG_CACHE_HOME=$WORK/home/.cache
unset XDG_RUNTIME_DIR GH_PATH GH_TOKEN GITHUB_TOKEN GH_APPAUTH_BROKER GH_APPAUTH_SECRET || true
export GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0
mkdir -p "$HOME"
git config --global init.defaultBranch main

echo "== phase 1: TLS with certificate files + ca_file"
start_broker -tls files -tls-cert "$WORK/tls.crt" -tls-key "$WORK/tls.key"

echo "== configure through the admin UI"
UI_CURL=(--cacert "$WORK/ca.pem")
ui_login "$BROKER_URL"
pass "admin UI login"
{ grep -q "App backend-bot saved" <<<"$(ui_post /ui/apps -F name=backend-bot -F app_id=1001 -F "private_key_file=@$WORK/app1.pem")"; } || fail "add PKCS#1 app"; pass "add PKCS#1 app"
{ grep -q "App frontend-bot saved" <<<"$(ui_post /ui/apps -F name=frontend-bot -F app_id=1002 -F "private_key_file=@$WORK/app2.pem")"; } || fail "add PKCS#8 app"; pass "add PKCS#8 app"
{ grep -q "works" <<<"$(ui_post /ui/apps/backend-bot/test)"; } || fail "test app against GitHub"; pass "test app against GitHub"
PAGE=$(ui_post /ui/clients -F name=e2e -F allowed_cidrs=127.0.0.0/8)
SECRET=$(sed -n 's#.*<code id="secret">\([^<]*\)</code>.*#\1#p' <<<"$PAGE")
[[ "$SECRET" == gaa_* ]] || fail "create client shows secret"; pass "create client shows secret"
{ grep -q "Grant saved" <<<"$(ui_post /ui/clients/e2e/grants -F app=backend-bot -F 'repos=acme/api-*' \
    -F perm_contents=write -F perm_pull_requests=write -F perm_metadata=read)"; } || fail "add grant"
{ grep -q "Grant saved" <<<"$(ui_post /ui/clients/e2e/grants -F app=frontend-bot -F repos=acme/web)"; } || fail "add grant"
pass "add grants"
{ grep -q "2 app(s), 1 client(s), 1 secret(s), 2 grant(s)" <<<"$("$BROKER" check -db "$DB")"; } || fail "check"; pass "check"

echo "== client"
{ printf '%s\n' "$SECRET" | "$EXT" setup --broker "$BROKER_URL" --ca-file "$WORK/ca.pem" >/dev/null; } || fail "setup with ca_file"; pass "setup with ca_file"
if printf '%s\n' "$SECRET" | "$EXT" setup --broker "$BROKER_URL" >/dev/null 2>&1; then fail "setup without trust should fail"; fi
pass "untrusted certificate rejected"
# The failed setup must not have overwritten the good config.
{ grep -q 'Client:  e2e' <<<"$("$EXT" status)"; } || fail "status shows client"; pass "status shows client"

"$EXT" git-setup >/dev/null
{ grep -q "git-credential" <<<"$(git config --global --get-all credential.https://github.com.helper)"; } || fail "git-setup configured helper"; pass "git-setup configured helper"

REPO=$WORK/repo
git init -q "$REPO"
cd "$REPO"
git remote add origin https://github.com/acme/api-core.git

OUT=$(printf 'protocol=https\nhost=github.com\npath=acme/api-core.git\n\n' | git credential fill)
TOKEN=$(sed -n 's/^password=//p' <<<"$OUT")
{ [[ "$TOKEN" == ghs_* ]] && grep -q '^username=x-access-token' <<<"$OUT"; } || fail "git credential fill returns a token"; pass "git credential fill returns a token"
{ [[ "$("$EXT" token)" == "$TOKEN" ]]; } || fail "token for current repo matches (local cache)"; pass "token for current repo matches (local cache)"

if printf 'protocol=https\nhost=github.com\npath=acme/secret.git\n\n' | git credential fill >/dev/null 2>&1; then
  fail "repo outside the grant got a credential"
fi
pass "repo outside the grant refused"
if printf 'protocol=https\nhost=github.com\npath=acme/api-zzz.git\n\n' | git credential fill >/dev/null 2>&1; then
  fail "repo not in installation got a credential"
fi
pass "repo not in the App installation refused"

WEBTOK=$("$EXT" token acme/web)
{ [[ "$WEBTOK" == ghs_* && "$WEBTOK" != "$TOKEN" ]]; } || fail "different repo → different App token"; pass "different repo → different App token"

{ [[ "$("$EXT" repos acme | cut -f1,4 | tr '\t\n' ' ;')" == "acme/api-auth backend-bot;acme/api-core backend-bot;acme/web frontend-bot;" ]]; } || fail "repos lists granted repos"; pass "repos lists granted repos"

{ [[ "$(git config --local user.email)" == "555+backend-bot[bot]@users.noreply.github.com" ]]; } || fail "credential helper sets bot identity"; pass "credential helper sets bot identity"
git config --local --unset user.email
"$EXT" identity >/dev/null
{ [[ "$(git config user.email)" == "555+backend-bot[bot]@users.noreply.github.com" ]]; } || fail "identity sets bot email"; pass "identity sets bot email"

# A public repo's clone never asks for credentials, so the post-checkout hook
# sets the identity. Without a GitHub to clone from, `worktree add` stands in:
# it runs the hook with the same all-zero old ref as a clone.
if git hook list post-checkout 2>/dev/null | grep -q gh-appauth; then
  git init -q "$WORK/pub"
  git -C "$WORK/pub" remote add origin https://github.com/acme/api-auth.git
  git -C "$WORK/pub" -c user.name=x -c user.email=x@x commit -q --allow-empty -m init
  git -C "$WORK/pub" worktree add -q "$WORK/pub-wt" 2>/dev/null
  { [[ "$(git -C "$WORK/pub" config --local user.email)" == "555+backend-bot[bot]@users.noreply.github.com" ]]; } || fail "post-checkout hook sets bot identity"
  pass "post-checkout hook sets bot identity"
  git -C "$WORK/pub" -c gh-appauth.coAuthor="Me <me@example.com>" commit -q --allow-empty -m co
  { [[ "$(git -C "$WORK/pub" log -1 --format='%(trailers:key=Co-authored-by,valueonly)')" == "Me <me@example.com>" ]]; } || fail "prepare-commit-msg hook adds Co-authored-by"
  pass "prepare-commit-msg hook adds Co-authored-by"
else
  echo "  skip post-checkout hook (git $(git --version | cut -d' ' -f3) has no config-defined hooks)"
fi

echo "== gh shim"
mkdir -p "$WORK/realgh"
cat > "$WORK/realgh/gh" <<'EOF'
#!/bin/sh
echo "TOKEN=${GH_TOKEN:-} GITHUB_TOKEN=${GITHUB_TOKEN:-} ARGS=$*"
EOF
chmod +x "$WORK/realgh/gh"
PATH="$WORK/realgh:$PATH" "$EXT" shim "$WORK/shim" >/dev/null
export PATH="$WORK/shim:$WORK/realgh:$PATH"
[[ "$(command -v gh)" == "$WORK/shim/gh" ]] || fail "shim not first in PATH"
{ grep -q "TOKEN=$TOKEN " <<<"$(gh pr list)"; } || fail "shim: current-folder repo"; pass "shim: current-folder repo"
{ grep -q "TOKEN=$WEBTOK " <<<"$(gh pr list -R acme/web)"; } || fail "shim: -R flag"; pass "shim: -R flag"
{ grep -q "TOKEN=$WEBTOK " <<<"$(gh pr list --repo=acme/web)"; } || fail "shim: --repo= flag"; pass "shim: --repo= flag"
{ grep -q "TOKEN= GITHUB_TOKEN= ARGS=--version" <<<"$(GITHUB_TOKEN=leak gh --version)"; } || fail "shim: pass-through strips tokens"; pass "shim: pass-through strips tokens"
{ (cd "$WORK" && grep -q "TOKEN= " <<<"$(gh pr list)"); } || fail "shim: no repo → no token"; pass "shim: no repo → no token"
{ (cd "$WORK" && grep -q "TOKEN=$WEBTOK " <<<"$(gh repo clone acme/web)"); } || fail "shim: repo clone outside a repo"; pass "shim: repo clone outside a repo"
{ grep -q "TOKEN=$WEBTOK " <<<"$(gh repo clone -u up acme/web)"; } || fail "shim: repo clone inside another repo"; pass "shim: repo clone inside another repo"
{ ! gh repo clone web >/dev/null 2>&1; } || fail "shim: bare repo name refused"; pass "shim: bare repo name refused"
{ grep -q "TOKEN=$WEBTOK " <<<"$(gh pr view https://github.com/acme/web/pull/1 -R acme/api-core)"; } || fail "shim: PR URL beats -R"; pass "shim: PR URL beats -R"
{ grep -q "TOKEN=$TOKEN " <<<"$(gh pr comment 1 --body https://github.com/acme/web/pull/1)"; } || fail "shim: URL in --body ignored"; pass "shim: URL in --body ignored"
{ grep -q "TOKEN=$WEBTOK " <<<"$(GH_REPO=acme/web gh pr list)"; } || fail "shim: GH_REPO"; pass "shim: GH_REPO"
git remote add upstream https://github.com/acme/web
{ grep -q "TOKEN=$WEBTOK " <<<"$(gh pr list)"; } || fail "shim: upstream remote beats origin"; pass "shim: upstream remote beats origin"
git config remote.origin.gh-resolved base
{ grep -q "TOKEN=$TOKEN " <<<"$(gh pr list)"; } || fail "shim: gh repo set-default"; pass "shim: gh repo set-default"
git config --unset remote.origin.gh-resolved
git remote remove upstream
{ grep -q "TOKEN=$TOKEN GITHUB_TOKEN=$TOKEN" <<<"$(GH_TOKEN=other "$EXT" exec -- "$WORK/realgh/gh")"; } || fail "exec sets GH_TOKEN and GITHUB_TOKEN"; pass "exec sets GH_TOKEN and GITHUB_TOKEN"
# `gh extension upgrade` rewrites the extension binary while gh runs; that
# fails with "text file busy" if the shim is still running as gh's parent.
# Linux frees the binary a few ms after the exec, hence the retries.
mkdir -p "$WORK/upgrade/realgh"
cp "$EXT" "$WORK/upgrade/ext"
cat > "$WORK/upgrade/realgh/gh" <<'EOF'
#!/bin/sh
for _ in $(seq 50); do cp "$2" "$3" 2>/dev/null && exit 0; sleep 0.1; done
exit 1
EOF
chmod +x "$WORK/upgrade/realgh/gh"
export XDG_CONFIG_HOME=$WORK/upgrade/config
PATH="$WORK/upgrade/realgh:$PATH" "$WORK/upgrade/ext" shim "$WORK/upgrade/shim" >/dev/null
{ "$WORK/upgrade/shim/gh" extension "$EXT" "$WORK/upgrade/ext"; } || fail "shim: extension can replace its own binary"; pass "shim: extension can replace its own binary"
export XDG_CONFIG_HOME=$WORK/home/.config

echo "== erase / invalidate"
printf 'protocol=https\nhost=github.com\npath=acme/api-core.git\nusername=x-access-token\npassword=%s\n\n' "$TOKEN" | git credential reject
NEWTOK=$("$EXT" token)
{ [[ "$NEWTOK" != "$TOKEN" ]]; } || fail "credential reject → fresh token from broker"; pass "credential reject → fresh token from broker"

echo "== audit"
{ grep -q '"event":"issued"' "$WORK/audit.log" && grep -q '"event":"denied"' "$WORK/audit.log" && grep -q '"event":"invalidated"' "$WORK/audit.log" && grep -q '"event":"listed"' "$WORK/audit.log"; } || fail "audit log has issued/denied/invalidated/listed"; pass "audit log has issued/denied/invalidated/listed"
if grep -q "$TOKEN" "$WORK/audit.log" "$WORK/broker.log" || grep -q "$SECRET" "$WORK/audit.log" "$WORK/broker.log"; then fail "token or secret leaked to logs"; fi
pass "no tokens or secrets in logs"
stop_broker

echo "== phase 2: self-signed TLS + fingerprint pin"
start_broker -tls self -tls-hosts 127.0.0.1
FP=$("$BROKER" fingerprint -db "$DB")
{ grep -q "$FP" "$WORK/broker.log"; } || fail "fingerprint printed at startup matches CLI"; pass "fingerprint printed at startup matches CLI"
{ printf '%s\n' "$SECRET" | "$EXT" setup --broker "$BROKER_URL" --fingerprint "$FP" >/dev/null; } || fail "setup with fingerprint"; pass "setup with fingerprint"
"$EXT" cache clear >/dev/null
{ [[ "$("$EXT" token)" == ghs_* ]]; } || fail "token over pinned TLS"; pass "token over pinned TLS"
UI=$(curl -sk "$BROKER_URL/ui/login")
{ grep -q 'name="password"' <<<"$UI"; } || fail "admin UI served on API port"; pass "admin UI served on API port"
stop_broker

echo "== phase 3: TLS off, separate admin port"
start_broker -tls off -ui-listen 127.0.0.1:0
{ printf '%s\n' "$SECRET" | "$EXT" setup --broker "$BROKER_URL" >/dev/null; } || fail "setup over http to loopback"; pass "setup over http to loopback"
"$EXT" cache clear >/dev/null
{ [[ "$("$EXT" token)" == ghs_* ]]; } || fail "token over plain HTTP"; pass "token over plain HTTP"
{ [[ "$(curl -s -o /dev/null -w '%{http_code}' "$BROKER_URL/ui/login")" == 404 ]]; } || fail "UI not on API port"; pass "UI not on API port"
UIURL=$(sed -n 's/.*admin UI listening on \([^ ]*\).*/\1/p' "$WORK/broker.log" | head -1)
{ grep -q 'name="password"' <<<"$(curl -s "$UIURL/ui/login")"; } || fail "UI on its own port"; pass "UI on its own port"

# Revocation through the UI on its own port, then a SIGHUP reload.
UI_CURL=()
ui_login "$UIURL"
ui_post /ui/clients/e2e -F allowed_cidrs=127.0.0.0/8 -F disabled=on >/dev/null
"$EXT" cache clear >/dev/null
if "$EXT" token >/dev/null 2>&1; then fail "disabled client still gets tokens"; fi
pass "client disabled in UI is refused immediately"
kill -HUP "$BROKER_PID"
sleep 0.5
{ grep -q "configuration reloaded" "$WORK/broker.log"; } || fail "SIGHUP reload"
[[ "$(curl -s "$BROKER_URL/healthz")" == ok ]] || fail "broker alive after SIGHUP"
if "$EXT" token >/dev/null 2>&1; then fail "disabled client got a token after SIGHUP"; fi
pass "SIGHUP reload keeps state"
stop_broker

echo "all e2e checks passed"
