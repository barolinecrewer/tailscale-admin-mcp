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
| `TS_OAUTH_CLIENT_ID`, `TS_OAUTH_CLIENT_SECRET` | Tailscale API client (scopes below) |
| `TS_AUTHKEY` or `TS_CLIENT_SECRET` | register the tsnet node (see "Two OAuth clients") |
| `TSNET_HOSTNAME`, `TSNET_TAGS`, `TSNET_DIR` | node name (`tailscale-admin-mcp`), advertised tags, state dir (`/state`, mount a volume) |
| `ALLOWED_LOGINS`, `ALLOWED_TAGS` | who may call the MCP |
| `TS_TAILNET`, `APERTURE_URL` | defaults `-`, `http://ai/aperture` |

## Two OAuth clients

Keep the API client and the node-registration client separate.

| Client | Scopes | Used for |
|---|---|---|
| API (`TS_OAUTH_*`) | `policy_file:read`, `devices:core:read` | `get_policy`, `validate_policy`, `preview_policy`, `list_devices` |
| same, to enable writes | add `policy_file` | `set_policy` |
| same, for device changes via `call_api` | add `devices:core` | tags, authorize, rename |
| Node (`TS_CLIENT_SECRET`) | `auth_keys` | registers the tsnet node |

A credential with `auth_keys` or `devices:core` must have tags, and it can only mint keys for those tags (or tags they own).
Give the node client `tag:tailscale-admin-mcp` and set `TSNET_TAGS` to match. The tag needs a `tagOwners` entry.
`call_api` and `describe_api` list each endpoint's required scope.

## Aperture

No credential. Aperture authorizes by tailnet identity, so the node's tag needs two grants, in different places:
- Aperture config (no `dst`): `{"src": ["tag:tailscale-admin-mcp"], "app": {"tailscale.com/cap/aperture": [{"role": "admin"}]}}`. Add `read_pricing: true` for `aperture_get_pricing`.
- Tailnet policy (with `dst`): `{"src": ["tag:tailscale-admin-mcp"], "dst": ["tag:aperture"], "ip": ["tcp:80", "tcp:443"]}`.

`aperture_get_config` redacts provider API keys. Don't edit its output and send it back with `aperture_set_config`; edit the rendered infra template instead.

## Spec drift

`search_api`/`describe_api` read the live OpenAPI spec (`https://api.tailscale.com/api/v2`) at runtime. The hand-written tools use fixed paths, so
`.github/workflows/spec-drift.yml` fetches the spec weekly and fails if those paths or their OAuth scopes change.

## Aperture spec (optional)

`.github/workflows/aperture-spec.yml` joins the tailnet as an ephemeral `tag:ci` runner, downloads `<APERTURE_URL>/openapi.json`, checks the endpoints this server uses, and uploads the spec as an artifact. It does nothing unless the repo variable `APERTURE_URL` is set.
Also set secrets `TS_OAUTH_CLIENT_ID`/`TS_OAUTH_CLIENT_SECRET` (an OAuth client with `auth_keys` and `tag:ci`), add `tag:ci` to `tagOwners`, and grant `tag:ci` access to your Aperture host on `tcp:80`.
