#!/usr/bin/env bash
# Runs the broker against a fake GitHub with seeded apps, clients, grants,
# tokens and denied requests, for working on the admin UI. Runs offline.
# Usage: scripts/dev.sh [--reset]    (env PORT, default 8443)
#
# Rebuilds on every run, since the UI is embedded in the binary. State lives
# in .dev/ and is kept between runs; --reset seeds it from scratch. The fake
# GitHub forgets its tokens on restart, so revoking a token issued by an
# earlier run fails.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$ROOT/.dev
PORT=${PORT:-8443}
PASSWORD=dev-admin-password
URL=http://127.0.0.1:$PORT

PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM
fail() { echo "dev.sh: $*" >&2; exit 1; }

if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
  fail "port $PORT is in use; set PORT to use another"
fi

[[ "${1:-}" == --reset ]] && rm -rf "$WORK"
SEED=
[[ -f "$WORK/broker.db" ]] || SEED=1
mkdir -p "$WORK/bin"

(cd "$ROOT" && go build -o "$WORK/bin/gh-appauth-broker" ./cmd/gh-appauth-broker \
  && go build -o "$WORK/bin/fakegithub" ./testdata/fakegithub)
BROKER=$WORK/bin/gh-appauth-broker

if [[ -n "$SEED" ]]; then
  openssl genrsa -traditional -out "$WORK/backend.pem" 2048 2>/dev/null
  openssl genrsa -traditional -out "$WORK/web.pem" 2048 2>/dev/null
  printf '%s\n' "$PASSWORD" | "$BROKER" set-password -db "$WORK/broker.db" >/dev/null
fi

# Enough permissions on one installation to give long lists in the UI.
cat > "$WORK/fakegh.json" <<EOF
{"apps": [
  {"id": 1001, "slug": "backend-bot", "bot_id": 555, "private_key_file": "$WORK/backend.pem",
   "installations": [{"id": 11, "owner": "acme", "repos": ["api-core", "api-auth", "api-billing", "infra"],
     "permissions": {"contents": "write", "pull_requests": "write", "issues": "write", "metadata": "read",
       "actions": "write", "checks": "write", "statuses": "write", "workflows": "write",
       "organization_custom_properties": "admin", "repository_hooks": "write", "administration": "write",
       "deployments": "write", "environments": "read", "security_events": "read", "secret_scanning_alerts": "read"}}]},
  {"id": 1002, "slug": "web-bot", "bot_id": 777, "private_key_file": "$WORK/web.pem",
   "installations": [{"id": 22, "owner": "acme", "repos": ["web", "docs"],
     "permissions": {"contents": "write", "metadata": "read", "pull_requests": "write", "pages": "write"}}]}
]}
EOF
rm -f "$WORK/fakegh.addr"
"$WORK/bin/fakegithub" -config "$WORK/fakegh.json" -addr-file "$WORK/fakegh.addr" 2>"$WORK/fakegh.log" &
PIDS+=($!)
for _ in $(seq 50); do [[ -s "$WORK/fakegh.addr" ]] && break; sleep 0.1; done
[[ -s "$WORK/fakegh.addr" ]] || fail "fake GitHub did not start: $(cat "$WORK/fakegh.log")"

: > "$WORK/broker.log"
"$BROKER" serve -db "$WORK/broker.db" -listen "127.0.0.1:$PORT" -tls off \
  -github-api "http://$(cat "$WORK/fakegh.addr")" >"$WORK/audit.log" 2>"$WORK/broker.log" &
BROKER_PID=$!
PIDS+=("$BROKER_PID")
until grep -q "API listening on" "$WORK/broker.log"; do
  kill -0 "$BROKER_PID" 2>/dev/null || fail "broker did not start: $(cat "$WORK/broker.log")"
  sleep 0.1
done

if [[ -n "$SEED" ]]; then
  echo "== seeding"
  curl -fsS -c "$WORK/jar" -o /dev/null -d "password=$PASSWORD" "$URL/ui/login"
  CSRF=$(curl -fsS -b "$WORK/jar" "$URL/ui/" | sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' | head -1)
  [[ -n "$CSRF" ]] || fail "admin UI login failed"
  post() { # $1 = path, rest = curl -F fields; prints the page after the redirect
    local path=$1 page; shift
    page=$(curl -fsS -L -b "$WORK/jar" -c "$WORK/jar" -F "csrf=$CSRF" "$@" "$URL$path")
    if grep -q 'class="flash err"' <<<"$page"; then
      fail "POST $path: $(sed -n 's/.*class="flash err".*<span>\(.*\)<\/span>.*/\1/p' <<<"$page")"
    fi
    printf '%s' "$page"
  }

  post /ui/apps -F name=backend -F app_id=1001 -F "private_key_file=@$WORK/backend.pem" >/dev/null
  post /ui/apps -F name=web -F app_id=1002 -F "private_key_file=@$WORK/web.pem" >/dev/null

  for c in claude-code-laptop codex-ci ci-runner; do
    post /ui/clients -F "name=$c" | sed -n 's#.*<code id="secret">\([^<]*\)</code>.*#\1#p' > "$WORK/$c.secret"
    [[ -s "$WORK/$c.secret" ]] || fail "create client $c"
  done
  post /ui/clients/claude-code-laptop/grants -F app=backend -F 'repos=acme/api-*' \
    -F perm_contents=write -F perm_pull_requests=write -F perm_issues=write -F perm_metadata=read \
    -F perm_actions=write -F perm_checks=write -F perm_statuses=write -F perm_workflows=write >/dev/null
  post /ui/clients/claude-code-laptop/grants -F app=web -F $'repos=acme/web\nacme/docs' \
    -F perm_contents=write -F perm_pull_requests=write -F perm_metadata=read >/dev/null
  post /ui/clients/codex-ci/grants -F app=backend -F $'repos=acme/infra\nacme/api-core' >/dev/null
  post /ui/clients/ci-runner/grants -F app=backend -F 'repos=acme/*' -F perm_contents=read -F perm_metadata=read >/dev/null

  token() { # $1 = client, $2 = repo, $3 = expected HTTP status, $4 = optional permissions JSON
    local status
    status=$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $(cat "$WORK/$1.secret")" \
      -d "{\"repository\":\"$2\"${4:+,\"permissions\":$4}}" "$URL/v1/token")
    [[ "$status" == "$3" ]] || fail "token $1 $2: got HTTP $status, want $3"
  }
  token claude-code-laptop acme/api-core 200
  token claude-code-laptop acme/api-core 200   # served from the cache
  token claude-code-laptop acme/api-auth 200 '{"contents":"read","metadata":"read"}'
  token claude-code-laptop acme/web 200
  token claude-code-laptop acme/secrets 403    # no grant
  token codex-ci acme/infra 200
  token codex-ci acme/api-core 200 '{"contents":"write","metadata":"read"}'
  token ci-runner acme/api-billing 200
  token ci-runner acme/api-core 403 '{"contents":"write","metadata":"read"}'   # exceeds the grant
  token ci-runner acme/docs 403 '{"contents":"read","pages":"write","bogus_perm":"superuser"}'   # invalid level
fi

echo "Admin UI: $URL/ui/  (password: $PASSWORD)"
echo "Logs: $WORK/broker.log, $WORK/audit.log. Ctrl-C stops."
wait "$BROKER_PID"
