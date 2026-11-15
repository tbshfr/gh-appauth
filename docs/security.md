# Security model

The broker limits what a leaked agent credential can do. It doesn't stop an agent from using the access you gave it: an agent that holds a client secret can still get tokens for the repos it's granted, with the permissions in its grants.

What the broker adds:

- The App private key never leaves the broker host, so it can't be stolen from an agent machine.
- Each client has its own secret, and you can revoke it in one place (the admin UI or the database). Revoking a client, removing or narrowing a grant, or replacing an App also revokes the affected live tokens at GitHub.
- Permissions are capped per grant, and every token covers a single repo.
- The audit log is central: JSON lines on stdout, plus request history in the admin UI. Tokens and secrets are never logged.
- Optionally, a client's allowed source IPs or CIDRs make a copied secret useless from another address.
- Repeated failed authentications from one address are rate limited, and a limited address is refused even with a valid secret.

## Network exposure

The client secret travels over the network. Use TLS (the default is a self-signed certificate that clients pin) unless the network really is trusted, and don't expose the broker to the internet.

Keep the admin UI away from the agents. The example systemd unit serves it on a separate port bound to loopback, so a machine that can reach the token API still can't reach the login page. See [Admin UI](broker.md#admin-ui) for the session and cookie settings.

## On the agent machine

The agent's OS user should have no `gh auth login` session. Otherwise a `gh` command the shim can't tie to a repo falls back to your personal account.

Tokens are cached locally in a directory only the agent's user can read. If the broker refuses a request (401 or 403), the extension deletes the cached token and doesn't fall back to it, so revoking a client takes effect on the next request. Details are in [Local token cache](extension.md#local-token-cache).

## Backups

The database contains the App private keys. Store backups of it with the same care as the keys themselves.
