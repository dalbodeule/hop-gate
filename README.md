# HopGate

> Korean / English bilingual README. (ko/en 병기 README입니다.)

## 1. 프로젝트 개요 (Project Overview)

HopGate는 공인 서버와 여러 프라이빗 네트워크 클라이언트 사이에 **DTLS 기반 HTTP 터널**을 제공하는 게이트웨이입니다.  
HopGate is a gateway that provides a **DTLS-based HTTP tunnel** between a public server and multiple private-network clients.

주요 특징 (Key features):

- 서버는 80/443 포트를 점유하고, ACME(Let's Encrypt 등)로 TLS 인증서를 자동 발급/갱신합니다.  
  The server listens on ports 80/443 and automatically issues/renews TLS certificates via ACME (e.g. Let's Encrypt).
- 서버–클라이언트 간 전송은 DTLS 위에서 이루어지며, HTTP 요청/응답을 메시지로 터널링합니다.  
  Transport between server and clients uses DTLS, tunneling HTTP request/response messages.
- 관리 Plane(REST API)을 통해 도메인 등록/해제 및 클라이언트 API Key 발급을 수행합니다.  
  An admin management plane (REST API) handles domain registration/unregistration and client API key issuance.
- 로그는 JSON 구조 형태로 stdout 에 출력되며, Prometheus + Loki + Grafana 스택에 친화적으로 설계되었습니다.  
  Logs are JSON-structured and designed to work well with a Prometheus + Loki + Grafana stack.

아키텍처 세부 내용은 [`ARCHITECTURE.md`](ARCHITECTURE.md)에 정리되어 있습니다.  
Detailed architecture is documented in [`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## 2. 디렉터리 구조 (Directory Layout)

- 서버 엔트리 (Server entrypoint): [`cmd/server/main.go`](cmd/server/main.go)  
- 클라이언트 엔트리 (Client entrypoint): [`cmd/client/main.go`](cmd/client/main.go)
- 설정 로더 (Config loader): [`internal/config/config.go`](internal/config/config.go)
- DTLS 추상/구현 (DTLS abstraction & implementation): [`internal/dtls`](internal/dtls)
- 관리 Plane (Admin plane HTTP API): [`internal/admin`](internal/admin)
- 도메인 스키마 (Domain schema, ent): [`ent/schema/domain.go`](ent/schema/domain.go)

---

## 3. 빌드 및 실행 (Build & Run)

### 3.1 의존성 (Dependencies)

- Go 1.21+ 권장 (go.mod 상 버전보다 최신 Go 사용을 추천)  
  Go 1.21+ is recommended (even if go.mod specifies an older minor).
- PostgreSQL (추후 DomainValidator 실제 구현 시 필요)  
  PostgreSQL (only required when implementing real domain validation).

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

## 4. DTLS 핸드셰이크 테스트 (Testing DTLS Handshake)

HopGate는 DTLS 위에서 **도메인 + 클라이언트 API Key** 기반의 애플리케이션 레벨 핸드셰이크를 수행합니다.  
HopGate performs an application-level handshake over DTLS using **domain + client API key**.

### 4.1 서버 설정 예시 (Server .env example)

`.env`:

```env
HOP_SERVER_DTLS_LISTEN=:8443
HOP_SERVER_DEBUG=true
```

- `HOP_SERVER_DTLS_LISTEN`  
  DTLS 서버가 바인딩할 UDP 포트입니다. 예: `:8443`  
  UDP port for the DTLS server to bind on, e.g. `:8443`.
- `HOP_SERVER_DEBUG=true`  
  디버그 모드에서는 [`dtls.NewSelfSignedLocalhostConfig()`](internal/dtls/selfsigned.go) 를 사용해 self-signed localhost 인증서를 생성합니다.  
  In debug mode the server uses [`dtls.NewSelfSignedLocalhostConfig()`](internal/dtls/selfsigned.go) to generate a self-signed localhost certificate.

### 4.2 클라이언트 설정 예시 (Client .env example)

`.env`:

```env
HOP_CLIENT_SERVER_ADDR=localhost:8443
HOP_CLIENT_DOMAIN=test.example.com
HOP_CLIENT_API_KEY=TEST_LOCALHOST_API_KEY_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ
HOP_CLIENT_LOCAL_TARGET=127.0.0.1:8080
HOP_CLIENT_DEBUG=true
```

- `HOP_CLIENT_SERVER_ADDR` : DTLS 서버 주소 (예: `localhost:8443`)  
  DTLS server address, e.g. `localhost:8443`.
- `HOP_CLIENT_DOMAIN` / `HOP_CLIENT_API_KEY` : 관리 Plane 에서 발급받은 도메인/키 (현재는 DummyValidator 로 아무 값이나 허용)  
  Domain and API key issued by the admin plane (currently any values are accepted by DummyValidator).
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
- 실제 운영 시에는 ACME 기반 인증서, PostgreSQL + ent 기반 DomainValidator, Proxy 레이어 연동 등을 완성해야 합니다.  
  For production you must wire ACME certificates, a PostgreSQL+ent-based DomainValidator, and the proxy layer.

HopGate는 아직 초기 단계의 실험적 프로젝트입니다. API 및 동작은 언제든지 변경될 수 있습니다.  
HopGate is still experimental; APIs and behavior may change at any time.
