# HopGate

> Korean / English bilingual README. (ko/en 병기 README입니다.)

## 1. 프로젝트 개요 (Project Overview)

HopGate는 공인 서버와 여러 프라이빗 네트워크 클라이언트 사이에 **TLS + yamux 기반 HTTP 터널**을 제공하는 게이트웨이입니다.
HopGate is a gateway that provides a **TLS + yamux HTTP tunnel** between a public server and multiple private-network clients.

주요 특징 (Key features):

- 서버는 80/443 포트를 점유하고, ACME(Let's Encrypt 등)로 TLS 인증서를 자동 발급/갱신합니다.
  The server listens on ports 80/443 and automatically issues/renews TLS certificates via ACME (e.g. Let's Encrypt).
- 서버–클라이언트 간 기본 전송은 TLS 위의 TCP와 yamux이며, 하나의 연결에 여러 HTTP logical stream을 multiplex합니다.
  The default transport is TCP + TLS with yamux multiplexing, carrying multiple HTTP logical streams over one connection.
- 관리 Plane(REST API)을 통해 도메인 등록/해제 및 클라이언트 API Key 발급을 수행합니다.
  An admin management plane (REST API) handles domain registration/unregistration and client API key issuance.
- 로그는 JSON 구조 형태로 stdout 에 출력되며, Prometheus + Loki + Grafana 스택에 친화적으로 설계되었습니다.
  Logs are JSON-structured and designed to work well with a Prometheus + Loki + Grafana stack.

> 참고: yamux logical stream은 HTTP/1.1 wire format을 사용하지만, 요청과 응답 body는 버퍼 전체를 메모리에 올리지 않고 스트리밍됩니다. SSE는 연결이 유지되는 동안 이벤트를 즉시 전달합니다. (ko)
> Note: yamux logical streams use HTTP/1.1 wire format, while request and response bodies are streamed without buffering the entire payload in memory. SSE events are delivered while the connection remains open. (en)

아키텍처 세부 내용은 [`ARCHITECTURE.md`](ARCHITECTURE.md)에 정리되어 있습니다.  
Detailed architecture is documented in [`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## 2. 디렉터리 구조 (Directory Layout)

- 서버 엔트리 (Server entrypoint): [`cmd/server/main.go`](cmd/server/main.go)  
- 클라이언트 엔트리 (Client entrypoint): [`cmd/client/main.go`](cmd/client/main.go)
- 설정 로더 (Config loader): [`internal/config/config.go`](internal/config/config.go)
- TLS + yamux 터널 (TLS + yamux tunnel): [`internal/tunnel`](internal/tunnel)
- 관리 Plane (Admin plane HTTP API): [`internal/admin`](internal/admin)
- 도메인 스키마 (Domain schema, ent): [`ent/schema/domain.go`](ent/schema/domain.go)

---

## 3. 빌드 및 실행 (Build & Run)

### 3.1 의존성 (Dependencies)

- Go 1.27.0+ 필요
  Go 1.27.0 or newer is required.
- PostgreSQL (관리 Plane + 실제 DomainValidator 에 필수)
  PostgreSQL (required for the admin plane and the real DomainValidator).

Go 모듈 의존성 설치 / 정리는 다음으로 수행할 수 있습니다:  
You can install/cleanup Go module deps via:

```bash
go mod tidy
```

### 3.2 Makefile 사용 (Using Makefile)

서버/클라이언트 빌드를 위해 상위 [`Makefile`](Makefile)을 제공합니다.
A top-level [`Makefile`](Makefile) is provided for server/client builds.

```bash
# 서버/클라이언트 모두 빌드
make all

# 서버만 빌드
make server

# 클라이언트만 빌드
make client
```

빌드 결과는 `./bin/hop-gate-server`, `./bin/hop-gate-client` 로 생성됩니다.
Build artifacts are created as `./bin/hop-gate-server` and `./bin/hop-gate-client`.

---

### 3.3 환경변수와 .env 처리 (Environment variables and .env handling)

HopGate 는 공통 설정을 [`internal/config/config.go`](internal/config/config.go) 에서 로드하며,
**운영체제 환경변수(OS env)가 `.env` 파일보다 우선**하도록 설계되어 있습니다.
HopGate loads shared configuration from [`internal/config/config.go`](internal/config/config.go) and is designed so that **OS-level environment variables take precedence over `.env`**.

- `.env` 로더: [`loadDotEnvOnce`](internal/config/config.go)
  - 현재 작업 디렉터리의 `.env` 파일을 한 번만 읽습니다.
  - 이미 OS 환경변수에 설정된 키는 **덮어쓰지 않고 그대로 유지**하고, 비어 있는 키에 대해서만 `.env` 값을 주입합니다.
  - `.env` 파일이 존재하지 않으면 조용히 무시합니다 (에러가 아닙니다).
  The loader reads the `.env` file once, **does not override existing OS env values**, and only fills missing keys. If `.env` is missing, it is silently ignored.

- 서버 설정 로더 (Server config loader): [`LoadServerConfigFromEnv`](internal/config/config.go)
  - `.env` 로더를 먼저 호출한 뒤, `HOP_SERVER_*` 환경변수에서 서버 설정을 구성합니다.
  - 실제 실행 시점에는 서버 엔트리포인트 [`cmd/server/main.go`](cmd/server/main.go) 에서 필수 환경변수가 모두 설정되었는지 한 번 더 검증합니다.
  It calls the `.env` loader first, then builds server config from `HOP_SERVER_*` env vars, and finally the server entrypoint [`cmd/server/main.go`](cmd/server/main.go) validates required variables.

- 클라이언트 설정 로더 (Client config loader): [`LoadClientConfigFromEnv`](internal/config/config.go)
  - `.env` 로더를 동일하게 사용하며, `HOP_CLIENT_*` 환경변수에서 클라이언트 설정을 구성합니다.
  - 이후 CLI 인자(예: `--server-addr`, `--domain`)가 있을 경우 env 값보다 우선 적용됩니다.
  The same loader is used for `HOP_CLIENT_*` env vars, and CLI flags override env values when provided.

빌드/실행 시 필수 환경변수는 다음 두 단계에서 검증됩니다.
Required environment variables are validated in two stages:

1. **빌드 단계 (Build-time) – Makefile 체크 (optional guard)**
   - [`Makefile`](Makefile) 에서 `.env` 를 `include` 한 뒤, `check-env-server` / `check-env-client` 타깃으로 최소한의 필수 env 를 확인합니다.
   - 예) 서버 빌드 시: `make server` → `errors-css` → `check-env-server` → `go build` 순으로 실행됩니다.
   The [`Makefile`](Makefile) includes `.env` and uses `check-env-server` / `check-env-client` targets to guard required variables before build.

2. **실행 단계 (Runtime) – 엔트리포인트에서 엄격 검증 (strict runtime validation)**
   - 서버: [`cmd/server/main.go`](cmd/server/main.go)
     - 헬퍼 `getEnvOrPanic(logger, key)` 를 사용해 `HOP_SERVER_HTTP_LISTEN`, `HOP_SERVER_HTTPS_LISTEN`, `HOP_SERVER_DOMAIN`, `HOP_SERVER_DEBUG` 가 비어 있지 않은지 확인합니다.
     - 누락되었거나 공백인 경우, 구조화 에러 로그(JSON)와 함께 프로세스를 종료합니다.
   - 클라이언트: [`cmd/client/main.go`](cmd/client/main.go)
     - `HOP_CLIENT_SERVER_ADDR`, `HOP_CLIENT_DOMAIN`, `HOP_CLIENT_API_KEY`, `HOP_CLIENT_LOCAL_TARGET`, `HOP_CLIENT_DEBUG` 를 동일한 방식으로 검증합니다.
   - 두 경우 모두 `HOP_*_DEBUG` 값은 문자열 `"true"` 또는 `"false"` 만 허용합니다.
   Both server and client use a helper (`getEnvOrPanic`) to enforce non-empty required env vars at startup and log structured JSON errors on failure. The debug flags must be the strings `"true"` or `"false"`.

실제 배포 환경에서는 `.env` 보다는 시스템 환경변수(Kubernetes `env`, Docker `-e`, systemd `Environment=` 등)를 사용하는 것을 권장하며,
로컬 개발에서는 `.env.example` 을 복사한 `.env` 파일을 사용해 빠르게 설정을 구성할 수 있습니다.
For production deployments, prefer OS-level env (Kubernetes `env`, Docker `-e`, systemd `Environment=`, etc.), and use a local `.env` (copied from `.env.example`) mainly for development.

## 4. TLS + yamux 터널 설정 (TLS + yamux tunnel configuration)

HopGate는 TLS 연결 위의 yamux control stream에서 **도메인 + 클라이언트 API Key** 기반의 핸드셰이크를 수행합니다.
HopGate authenticates a yamux control stream using **domain + client API key**.

### 4.1 서버 설정 예시 (Server .env example)

`.env`:

```env
HOP_SERVER_TUNNEL_LISTEN=:7443
HOP_SERVER_DEBUG=true
```

- `HOP_SERVER_TUNNEL_LISTEN`
  TLS + yamux 서버가 바인딩할 TCP 포트입니다. 예: `:7443`
  TCP port for the TLS + yamux server to bind on, e.g. `:7443`.
- `HOP_SERVER_DEBUG=true`  
  디버그 모드에서는 인증서 검증을 생략할 수 있습니다. 이는 개발 환경에서만 사용해야 합니다.
  In debug mode certificate verification may be skipped. Use this only for development.

### 4.2 클라이언트 설정 예시 (Client .env example)

`.env`:

```env
HOP_CLIENT_SERVER_ADDR=localhost:7443
HOP_CLIENT_DOMAIN=test.example.com
HOP_CLIENT_API_KEY=TEST_LOCALHOST_API_KEY_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ
HOP_CLIENT_LOCAL_TARGET=127.0.0.1:8080
HOP_CLIENT_DEBUG=true
```

- `HOP_CLIENT_SERVER_ADDR` : yamux 터널 서버 주소 (예: `localhost:7443`)
  yamux tunnel server address, e.g. `localhost:7443`.
- `HOP_CLIENT_DOMAIN` / `HOP_CLIENT_API_KEY` : 관리 Plane 에서 발급받은 도메인/키 (실제 ent + PostgreSQL 기반 DomainValidator 에 의해 검증)
  Domain and API key issued by the admin plane (validated by a real ent + PostgreSQL based DomainValidator).
- `HOP_CLIENT_LOCAL_TARGET` : 실제로 HTTP 요청을 보낼 로컬 서버 주소
  Local HTTP target address.
- `HOP_CLIENT_DEBUG=true` : 서버 인증서 체인 검증을 스킵(InsecureSkipVerify)하여 self-signed 인증서를 신뢰  
  Skips server certificate chain verification (InsecureSkipVerify) and trusts the self-signed cert.

### 4.3 서버/클라이언트 실행 (Run server/client)

```bash
# 서버 실행 (Server)
./bin/hop-gate-server

# 클라이언트 실행 (Client)
./bin/hop-gate-client
```

HTTP/3 ingress를 사용하려면 서버의 TCP HTTPS 포트와 동일한 UDP 포트를 외부에 노출해야 합니다.
HTTP/3 ingress requires exposing the same port as the HTTPS listener over UDP.

HTTP/2 Extended CONNECT를 사용하는 클라이언트가 있는 경우 Go HTTP/2의
호환성 설정을 켜고 서버를 실행합니다.
For HTTP/2 Extended CONNECT clients, enable Go's compatibility setting:

```bash
GODEBUG=http2xconnect=1 ./bin/hop-gate-server
```

성공 시 로그에는 다음과 같은 정보가 찍힙니다.  
On success, logs will include information like:

- 서버: 세션 ID, 연결된 도메인  
  Server: session ID and connected domain.
- 클라이언트: 핸드셰이크 성공 메시지, 도메인, local_target  
  Client: handshake success message, domain, and local_target.

로그 출력 형식은 구조적 JSON 이며, Loki/Grafana 에서 쉽게 수집/조회할 수 있습니다.  
Logs are JSON-structured and easy to ingest/query with Loki/Grafana.

---

## 5. 관리 Plane 요약 (Admin Plane Summary)

관리 Plane 은 `https://{server-hostname}/api/v1/admin` 하위 경로로 동작합니다.  
The admin plane is served under `https://{server-hostname}/api/v1/admin`.

- 인증 (Authentication)  
  - 헤더 `Authorization: Bearer {ADMIN_API_KEY}` 사용  
    Uses `Authorization: Bearer {ADMIN_API_KEY}` header.

- 도메인 등록 (Domain register)  
  - `POST /api/v1/admin/domains/register`  
  - 요청(JSON): `{"domain":"example.com","memo":"text"}`  
  - 응답(JSON): 성공 시 `{"success":true,"client_api_key":"..."}`

- 도메인 해제 (Domain unregister)  
  - `POST /api/v1/admin/domains/unregister`  
  - 요청(JSON): `{"domain":"example.com","client_api_key":"..."}`  
  - 응답(JSON): `{"success":true}` 또는 에러 메시지

자세한 구현 뼈대는 [`internal/admin`](internal/admin) 및 [`ent/schema/domain.go`](ent/schema/domain.go) 를 참고하세요.  
For implementation skeleton, see [`internal/admin`](internal/admin) and [`ent/schema/domain.go`](ent/schema/domain.go).

---

## 6. 주의사항 (Caveats)

- `Debug=true` 설정은 **개발/테스트 용도**입니다. self-signed 인증서 및 InsecureSkipVerify 사용은 프로덕션 환경에서 절대 사용하지 마세요.
  `Debug=true` is strictly for development/testing. Do not use self-signed certs or InsecureSkipVerify in production.
- 현재 yamux 경로는 HTTP/1.1·HTTP/2·HTTP/3 공개 요청, SSE, HTTP/1.1 WebSocket raw upgrade와 HTTP/2·HTTP/3 Extended CONNECT를 처리합니다.
  The yamux path handles public HTTP/1.1, HTTP/2, and HTTP/3 requests, SSE, HTTP/1.1 WebSocket raw upgrade, and HTTP/2 and HTTP/3 Extended CONNECT.

### Supported Ingress Protocols

| Ingress | 일반 HTTP | SSE | WebSocket 방식 |
| --- | --- | --- | --- |
| HTTP/1.1 | 지원 | 지원 | HTTP/1.1 Upgrade |
| HTTP/2 | 지원 | 지원 | Extended CONNECT |
| HTTP/3 | 지원 | 지원 | Extended CONNECT |

모든 ingress는 동일한 TLS + yamux 터널을 통해 클라이언트의 로컬 HTTP 서비스로 전달됩니다.
All ingress protocols use the same TLS + yamux tunnel to reach the client's local HTTP service.

### SSE and Extended CONNECT WebSocket

SSE responses are streamed through the yamux stream and do not use the normal
proxy timeout when the request accepts `text/event-stream`. This policy applies
to HTTP/1.1, HTTP/2, and HTTP/3 ingress alike; the client is responsible for
closing the request context when the SSE connection should end.

HTTP/2 WebSocket Extended CONNECT is enabled by the Go HTTP/2 implementation
with the following process setting:

```bash
GODEBUG=http2xconnect=1 go run ./cmd/server
```

The Extended CONNECT path translates the HTTP/2 or HTTP/3 WebSocket handshake
to the existing local HTTP/1.1 WebSocket connector, then relays the
bidirectional stream through yamux.

HopGate는 아직 초기 단계의 실험적 프로젝트입니다. API 및 동작은 언제든지 변경될 수 있습니다.
HopGate is still experimental; APIs and behavior may change at any time.
