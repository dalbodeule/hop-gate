# HopGate gRPC Tunnel Protocol

이 문서는 HopGate 서버–클라이언트 사이의 gRPC 기반 HTTP 터널링 규약을 정리합니다. (ko)
This document describes the gRPC-based HTTP tunneling protocol between HopGate server and clients. (en)

## 1. Transport Overview / 전송 개요

- Transport: TCP + TLS(HTTPS) + HTTP/2 + gRPC
- Single long-lived bi-directional gRPC stream per client: `OpenTunnel`
- Application payload type: `Envelope` (from `internal/protocol/hopgate_stream.proto`)
- HTTP requests/responses are multiplexed as logical streams identified by `StreamID`.

gRPC service (conceptual):
```proto
service HopGateTunnel {
  rpc OpenTunnel (stream Envelope) returns (stream Envelope);
}
```

## 2. Message Types / 메시지 타입

Defined in `internal/protocol/hopgate_stream.proto`:

- `HeaderValues`
  - Wraps repeated header values: `map<string, HeaderValues>`
- `Request` / `Response`
  - Simple single-message HTTP representation (not used in the streaming tunnel path initially).
- `StreamOpen`
  - Opens a new logical stream for HTTP request/response (or other protocols in the future).
- `StreamData`
  - Carries body chunks for a stream (`id`, `seq`, `data`).
- `StreamClose`
  - Marks the end of a stream (`id`, `error`).
- `StreamAck`
  - Legacy ARQ/flow-control hint for UDP/DTLS; in gRPC tunnel it is reserved/optional.
- `Envelope`
  - Top-level container with `oneof payload` of the above types.

In the gRPC tunnel, `Envelope` is the only gRPC message type used on the `OpenTunnel` stream.

## 3. Logical Streams and StreamID / 논리 스트림과 StreamID

- A single `OpenTunnel` gRPC stream multiplexes many **logical streams**.
- Each logical stream corresponds to one HTTP request/response pair.
- Logical streams are identified by `StreamOpen.id` (text StreamID).
- The server generates unique IDs per gRPC connection:
  - HTTP streams: `"http-{n}"` where `n` is a monotonically increasing counter.
  - Control stream: `"control-0"` (special handshake/metadata stream).

Within a gRPC connection:
- Multiple `StreamID`s may be active concurrently.
- Frames with different StreamIDs may be arbitrarily interleaved.
- Order within a stream is tracked by `StreamData.seq` (starting at 0).

## 4. HTTP Request Mapping (Server → Client) / HTTP 요청 매핑

When the public HTTPS reverse-proxy (`cmd/server/main.go`) receives an HTTP request for a domain that is bound
to a client tunnel, it serializes the request into a logical stream as follows.

### 4.1 StreamOpen (request metadata and headers)

- `StreamOpen.id`
  - New unique StreamID: `"http-{n}"`.
- `StreamOpen.service_name`
  - Logical service selection on the client (e.g., `"web"`).
- `StreamOpen.target_addr`
  - Optional explicit local target address on the client (e.g., `"127.0.0.1:8080"`).
- `StreamOpen.header`
  - Contains HTTP request headers and pseudo-headers:
  - Pseudo-headers:
    - `X-HopGate-Method`: HTTP method (e.g., `"GET"`, `"POST"`).
    - `X-HopGate-URL`: original URL path + query (e.g., `"/api/v1/foo?bar=1"`).
    - `X-HopGate-Host`: Host header value.
  - Other keys:
    - All remaining HTTP headers from the incoming request, copied as-is into the map.

### 4.2 StreamData* (request body chunks)

- If the request has a body, the server chunks it into fixed-size pieces.
- Chunk size: `protocol.StreamChunkSize` (currently 4 KiB).
- For each chunk:
  - `StreamData.id = StreamOpen.id`
  - `StreamData.seq` increments from 0, 1, 2, …
  - `StreamData.data` contains the raw bytes.

### 4.3 StreamClose (end of request body)

- After sending all body chunks, the server sends a `StreamClose`:
  - `StreamClose.id = StreamOpen.id`
  - `StreamClose.error` is empty on success.
  - If there was an application-level error while reading the body, `error` contains a short description.

The client reconstructs the HTTP request by:
- Reassembling the URL and headers from the `StreamOpen` pseudo-headers and header map.
- Concatenating `StreamData.data` in `seq` order into the request body.
- Treating `StreamClose` as the end-of-stream marker.

## 5. HTTP Response Mapping (Client → Server) / HTTP 응답 매핑

The client receives `StreamOpen` + `StreamData*` + `StreamClose`, performs a local HTTP request to its
configured target (e.g., `http://127.0.0.1:8080`), then returns an HTTP response using the same StreamID.

### 5.1 StreamOpen (response headers and status)

- `StreamOpen.id`
  - Same as the request StreamID.
- `StreamOpen.header`
  - Contains response headers and a pseudo-header for status:
  - Pseudo-header:
    - `X-HopGate-Status`: HTTP status code as a string (e.g., `"200"`, `"502"`).
  - Other keys:
    - All HTTP response headers from the local backend, copied as-is.

### 5.2 StreamData* (response body chunks)

- The client reads the local HTTP response body and chunks it into 4 KiB pieces (same `StreamChunkSize`).
- For each chunk:
  - `StreamData.id = StreamOpen.id`
  - `StreamData.seq` increments from 0.
  - `StreamData.data` contains the raw bytes.

### 5.3 StreamClose (end of response body)

- When the local backend response is fully read, the client sends a `StreamClose`:
  - `StreamClose.id` is the same StreamID.
  - `StreamClose.error`:
    - Empty string on success.
    - Short error description if the local HTTP request/response failed (e.g., connect timeout).

The server reconstructs the HTTP response by:
- Parsing `X-HopGate-Status` into an integer HTTP status code.
- Copying other headers into the outgoing response writer (with some security headers overridden by the server).
- Concatenating `StreamData.data` in `seq` order into the HTTP response body.
- Considering `StreamClose.error` for logging/metrics and possibly mapping to error pages if needed.

## 6. Control / Handshake Stream / 컨트롤 스트림

Before any HTTP request streams are opened, the client sends a single **control stream** to authenticate
and describe itself.

- `StreamOpen` (control):
  - `id = "control-0"`
  - `service_name = "control"`
  - `header` contains:
    - `X-HopGate-Domain`: domain this client is responsible for.
    - `X-HopGate-API-Key`: client API key for the domain.
    - `X-HopGate-Local-Target`: default local target such as `127.0.0.1:8080`.
- No `StreamData` is required for the control stream in the initial design.
- The server can optionally reply with its own control `StreamOpen/Close` to signal acceptance/rejection.

On the server side:
- `grpcTunnelServer.OpenTunnel` should:
  1. Wait for the first `Envelope` with `StreamOpen.id == "control-0"`.
  2. Extract domain, api key, and local target from the headers.
  3. Call the ent-based `DomainValidator` to validate `(domain, api_key)`.
  4. If validation succeeds, register this gRPC stream as the active tunnel for that domain.
  5. If validation fails, log and close the gRPC stream.

Once the control stream handshake completes successfully, the server may start multiplexing multiple
HTTP request streams (`http-0`, `http-1`, …) over the same `OpenTunnel` connection.

## 7. Multiplexing Semantics / 멀티플렉싱 의미

- A single TCP + TLS + HTTP/2 + gRPC connection carries:
  - One long-lived `OpenTunnel` gRPC bi-di stream.
  - Within it, many logical streams identified by `StreamID`.
- The server can open multiple HTTP streams concurrently for a given client:
  - Example: `http-0` for `/css/app.css`, `http-1` for `/api/users`, `http-2` for `/img/logo.png`.
  - Frames for these IDs can interleave arbitrarily on the wire.
- Per-stream ordering is preserved by combining `seq` ordering and the reliability of TCP/gRPC.
- Slow or large responses on one stream should not prevent other streams from making progress,
  because gRPC/HTTP2 handles stream-level flow control and scheduling.

## 8. Flow Control and StreamAck / 플로우 컨트롤 및 StreamAck

- The gRPC tunnel runs over TCP/HTTP2, which already provides:
  - Reliable, in-order delivery.
  - Connection-level and stream-level flow control.
- Therefore, application-level selective retransmission is **not required** for the gRPC tunnel.
- `StreamAck` remains defined in the proto for backward compatibility with the DTLS design and
  as a potential future hint channel (e.g., window size hints), but is not used in the initial gRPC tunnel.

## 9. Security Considerations / 보안 고려사항

- TLS:
  - In production, the server uses ACME-issued certificates, and clients validate the server certificate
    using system Root CAs and SNI (`ServerName`).
  - In debug mode, clients may use `InsecureSkipVerify: true` to allow local/self-signed certs.
- Authentication:
  - Application-level authentication relies on `(domain, api_key)` pairs sent via the control stream headers.
  - The server must validate these pairs against the `Domain` table using `DomainValidator`.
- Authorization and isolation:
  - Each gRPC tunnel is bound to a single domain (or a defined set of domains) after successful control handshake.
  - HTTP requests for other domains must not be forwarded over this tunnel.

이 규약을 기준으로 서버/클라이언트 구현을 정렬하면, 하나의 gRPC `OpenTunnel` 스트림 위에서
여러 HTTP 요청을 안정적으로 멀티플렉싱하면서도, 도메인/API 키 기반 인증과 TLS 보안을 함께 유지할 수 있습니다.