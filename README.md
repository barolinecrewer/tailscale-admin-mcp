# tailscale-admin-mcp

MCP server for the Tailscale API (policy file, devices, any endpoint in the OpenAPI spec) and the Aperture admin API.
Writes (`set_policy`, `aperture_set_config`) require the ETag from the matching read.

## Run

```sh
just run      # stdio, creds from 1Password
just docker   # image; runs as its own tailnet node (tsnet)
```

In `-tsnet` mode (the image's default) it joins the tailnet as a node and serves `https://<TSNET_HOSTNAME>.<tailnet>.ts.net/mcp`.
Each request is checked with `WhoIs`: the caller's login must be in `ALLOWED_LOGINS`, or its tag in `ALLOWED_TAGS`. Both empty means it refuses to start.
Aperture calls go out through that node, so grant the node's tag admin on Aperture.

| Env | Purpose |
|---|---|
| `TS_OAUTH_CLIENT_ID`, `TS_OAUTH_CLIENT_SECRET` | Tailscale API (scopes: `policy_file`, `devices:core:read`) |
| `TS_AUTHKEY` or `TS_CLIENT_SECRET` | register the tsnet node (the OAuth client secret also needs `auth_keys` and `TSNET_TAGS`) |
| `TSNET_HOSTNAME`, `TSNET_TAGS`, `TSNET_DIR` | node name (`tailscale-admin-mcp`), advertised tags, state dir (`/state`, mount a volume) |
| `ALLOWED_LOGINS`, `ALLOWED_TAGS` | who may call the MCP |
| `TS_TAILNET`, `APERTURE_URL` | defaults `-`, `http://ai/aperture` |
