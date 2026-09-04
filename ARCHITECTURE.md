# HopGate Architecture

HopGate exposes public HTTP traffic and forwards it to a private HTTP service
through an outbound client connection.

```text
public HTTP/HTTPS :80/:443
        |
        v
HopGate server -- TLS/TCP :7443 -- yamux -- HopGate client -- localhost HTTP
```

The client opens one TLS connection to the server and authenticates with a
yamux control stream containing the registered domain and API key. Each HTTP
request uses one bidirectional yamux stream. The stream begins with a bounded
JSON metadata record and then carries the HTTP/1.1 wire representation.

The public Go HTTP server handles HTTP/1.1 and HTTP/2. HTTP/3 and WebSocket
upgrade support are planned ingress features; they can reuse the same yamux
stream abstraction.

## Packages

- `internal/tunnel`: TLS dialing, yamux sessions, stream metadata, and responses.
- `cmd/server`: public HTTP/HTTPS ingress and yamux tunnel listener.
- `cmd/client`: outbound yamux client and local HTTP forwarding.
- `internal/admin`: domain registration and API-key validation.
- `internal/acme`: certificate acquisition and renewal.

The tunnel is intentionally stream-oriented. It does not implement application
ACKs or retransmission; TCP and yamux provide ordered reliable delivery.
