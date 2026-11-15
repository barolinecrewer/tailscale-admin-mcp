default:
    @just --list

build:
    go build -o tailscale-admin-mcp .

# Lint
check:
    gofmt -l . | (! grep .)
    go vet ./...

fmt:
    gofmt -w .

# Run over stdio, Tailscale API creds from 1Password
run:
    TS_OAUTH_CLIENT_ID="$(op read op://git-secrets/tailscale-gitops-oauth/client-id)" \
    TS_OAUTH_CLIENT_SECRET="$(op read op://git-secrets/tailscale-gitops-oauth/client-secret)" \
    go run .

docker:
    docker build -t tailscale-admin-mcp .
