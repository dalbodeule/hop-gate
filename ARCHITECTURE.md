# HopGate Architecture

HopGate exposes public HTTP traffic and forwards it to a private HTTP service
through one outbound TLS connection per client.

```text
                    TCP :80/:443  HTTP/1.1, HTTP/2
public clients  ------------------------------->  HopGate server
                    UDP :443     HTTP/3              |
                                                     | TLS/TCP
                                                     v
                                      yamux logical streams
                                                     |
                                                     v
                                           HopGate client
                                                     |
                                                     v
                                             localhost HTTP
```

## Connection Model

The client opens one TLS connection to the server and the connection is
multiplexed by yamux. The first logical stream is a bounded JSON control stream
containing the registered domain, local target, and client API key. The server
authenticates this stream before registering the session for the domain.

Each public request creates one bidirectional yamux stream. Every stream starts
with a bounded JSON `StreamMeta` record and then carries HTTP/1.1 wire data.
The stream kinds currently used are:

- `control`: client registration and authentication metadata.
- `http`: ordinary HTTP requests and responses.
- `websocket`: HTTP/1.1 Upgrade and HTTP/2/HTTP/3 Extended CONNECT traffic.

Request and response bodies are copied between stream endpoints instead of
being accumulated in memory. Long-lived SSE connections therefore occupy one
yamux stream for their lifetime.

## Ingress Protocols

The public server uses one common `http.Handler` for all ingress protocols:

- HTTP/1.1: ordinary reverse proxy and raw WebSocket Upgrade.
- HTTP/2: ordinary reverse proxy, SSE, and RFC 8441 Extended CONNECT.
- HTTP/3: ordinary reverse proxy, SSE, and RFC 9220 Extended CONNECT.

HTTP/3 runs on a separate UDP listener using `quic-go/http3`, while the TCP
HTTP/HTTPS listeners continue to serve HTTP/1.1 and HTTP/2. HTTP/1.1 and HTTP/2
responses advertise HTTP/3 with `Alt-Svc`.

For HTTP/2 Extended CONNECT, Go's compatibility setting must be enabled when
starting the process:

```bash
GODEBUG=http2xconnect=1 ./bin/hop-gate-server
```

## Streaming Policies

Requests accepting `text/event-stream` are treated as SSE. They bypass the
normal request-level proxy timeout, and response writes are flushed to the
public client as they arrive. The client or upstream service is responsible for
closing the SSE request context.

WebSocket Extended CONNECT is translated to a local HTTP/1.1 WebSocket
handshake. After the handshake, the payload is relayed as a bidirectional raw
stream. HTTP/3 Extended CONNECT follows the same application path as HTTP/2.

## Packages

- `internal/tunnel`: TLS dialing, yamux sessions, metadata, and stream lifecycle.
- `cmd/server`: public HTTP/HTTPS/HTTP/3 ingress and yamux tunnel listener.
- `cmd/client`: outbound yamux client and local HTTP/WebSocket forwarding.
- `internal/admin`: domain registration and API-key validation.
- `internal/acme`: certificate acquisition, renewal, and TLS configuration.

The tunnel is intentionally stream-oriented. It does not implement application
ACKs or retransmission; TLS over TCP and yamux provide ordered reliable delivery.
