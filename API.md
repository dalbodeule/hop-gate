# HopGate API

## Public Ingress

Registered domains are served by the public listeners configured on the server.
The same request is forwarded to the client's `HOP_CLIENT_LOCAL_TARGET`.

| Protocol | Port | Supported behavior |
| --- | --- | --- |
| HTTP/1.1 | TCP `HOP_SERVER_HTTP_LISTEN` / `HOP_SERVER_HTTPS_LISTEN` | HTTP, SSE, WebSocket Upgrade |
| HTTP/2 | TCP `HOP_SERVER_HTTPS_LISTEN` | HTTP, SSE, WebSocket Extended CONNECT |
| HTTP/3 | UDP `HOP_SERVER_HTTPS_LISTEN` | HTTP, SSE, WebSocket Extended CONNECT |

HTTP/3 is announced to HTTP/1.1 and HTTP/2 clients with `Alt-Svc`. HTTP/2
Extended CONNECT requires `GODEBUG=http2xconnect=1` when starting the server.

### SSE

SSE is detected when the request `Accept` header contains `text/event-stream`.
The response is streamed without buffering and bypasses the normal proxy
timeout. The upstream should send standard SSE records separated by a blank
line, for example:

```text
data: hello

```

### WebSocket

HTTP/1.1 WebSocket uses `Upgrade: websocket`. HTTP/2 and HTTP/3 use Extended
CONNECT with `:protocol=websocket`. The local service may remain an ordinary
HTTP/1.1 WebSocket server; HopGate translates the Extended CONNECT handshake
before relaying the raw bidirectional payload.

## Admin API

Admin endpoints are served under `/api/v1/admin/` on `HOP_SERVER_DOMAIN` and
require `Authorization: Bearer $HOP_ADMIN_API_KEY`.

- `POST /api/v1/admin/domains/register`
  - Request: `{"domain":"app.example.com","memo":"optional"}`
  - Response includes the generated `client_api_key`.
- `POST /api/v1/admin/domains/unregister`
  - Request: `{"domain":"app.example.com","client_api_key":"..."}`

## Tunnel Configuration

The server listens for client tunnels on `HOP_SERVER_TUNNEL_LISTEN`, defaulting
to `:7443`. The client connects to that address with
`HOP_CLIENT_SERVER_ADDR`. The client only needs an outbound TCP connection.

Required client settings are `HOP_CLIENT_SERVER_ADDR`, `HOP_CLIENT_DOMAIN`,
`HOP_CLIENT_API_KEY`, `HOP_CLIENT_LOCAL_TARGET`, and `HOP_CLIENT_DEBUG`.

The tunnel is TLS over TCP with yamux multiplexing. The client only needs an
outbound TCP connection to the tunnel listener; public HTTP/3 traffic terminates
at the server and does not require QUIC support in the client.
