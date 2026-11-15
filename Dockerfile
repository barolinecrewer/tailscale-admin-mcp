FROM golang:1 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /tailscale-admin-mcp .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /tailscale-admin-mcp /tailscale-admin-mcp
ENV TSNET_DIR=/state
VOLUME /state
ENTRYPOINT ["/tailscale-admin-mcp", "-tsnet"]
