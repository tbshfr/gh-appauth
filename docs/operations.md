# Operations

| Task | Steps |
|---|---|
| Add a client | UI → Clients → New client. Give the secret to the agent machine and run `gh appauth setup`. |
| Rotate a secret | Client page → *Generate new secret*. Re-run `setup` on the client, then remove the old secret. Both work in the meantime. |
| Revoke a client | Client page → Disabled, or *Delete client*. It gets 401 immediately and its live tokens are revoked at GitHub. |
| Change a grant | Client page → edit or remove the grant. Live tokens the new grants no longer cover are revoked at GitHub. |
| Revoke one token | Dashboard → *Revoke*. |
| Rotate an App key | Generate a new key in GitHub, then Apps → save it under the same name. Delete the old key in GitHub. |
| Reload | UI changes apply immediately. `systemctl reload gh-appauth-broker` (SIGHUP) re-reads the database and TLS certificate files. An invalid state is rejected and the broker keeps running on the old one. |
| Check the config | `gh-appauth-broker check` validates the stored config and keys. |
| Logs | `journalctl -u gh-appauth-broker`. Audit lines are JSON: `{"ts","event","status","client","ip","repo","app","perms","cached","reason"}`. Tokens and secrets are never logged. |
| Backup | `sqlite3 broker.db ".backup broker.bak"`, or copy the database while the broker is stopped. The file contains private keys, so store backups accordingly. |

## Running behind a reverse proxy

[deploy/Caddyfile.example](../deploy/Caddyfile.example) puts Caddy in front of the broker to terminate TLS with automatic certificates. The broker then runs on loopback without TLS:

```bash
gh-appauth-broker serve -listen 127.0.0.1:8080 -tls off \
    -trusted-proxies 127.0.0.1/32 -ui-listen 127.0.0.1:8081
```

Set `-trusted-proxies` to the proxy's address. The broker then takes the client address from `X-Forwarded-For`, which allowed source IPs and the audit log depend on. Without it the header is ignored and every request appears to come from the proxy.

The example also limits each site by source address, so only the agent machines reach the API and only your workstation reaches the admin UI.
