# HopGate Progress / 진행 현황

이 문서는 HopGate 아키텍처 대비 현재 구현 상태와 이후 추가해야 할 작업을 정리한 Milestone 문서입니다. (ko)  
This document tracks implementation progress against the HopGate architecture and lists remaining milestones. (en)

---

## 1. High-level Status / 상위 수준 상태

- 아키텍처 문서 및 README 정리 완료 (ko/en 병기).
  Architecture and README are documented in both Korean and English.
- 서버/클라이언트 엔트리 포인트, DTLS 핸드셰이크, 기본 PostgreSQL/ent 스키마까지 1차 뼈대 구현 완료.
  First skeleton implementation is done for server/client entrypoints, DTLS handshake, and basic PostgreSQL/ent schema.
- 기본 Proxy 동작(HTTP ↔ DTLS 터널링), Admin API 비즈니스 로직, ACME 기반 인증서 관리는 구현 완료된 상태.
  Core proxying (HTTP ↔ DTLS tunneling), admin API business logic, and ACME-based certificate management are implemented.
- 스트림 ARQ, Observability, Hardening, ACME 고급 전략 등은 아직 남아 있는 다음 단계 작업이다.
  Stream-level ARQ, observability, hardening, and advanced ACME operational strategies remain as next-step work items.

---

## 2. Completed Work / 완료된 작업

### 2.1 Documentation / 문서

- 아키텍처 개요: [`ARCHITECTURE.md`](ARCHITECTURE.md)  
  - ko/en 병기, 전체 구조/디렉터리/흐름/다음 단계 정리. (ko)  
  - Bilingual, documents overall structure, directories, flows, and next steps. (en)

- 프로젝트 개요: [`README.md`](README.md)  
  - 사용법, DTLS 핸드셰이크 테스트 방법, Admin Plane 요약, 주의사항. (ko/en)  
  - Usage, DTLS handshake test guide, admin plane summary, caveats. (en)

- 커밋 규칙: [`COMMIT_MESSAGE.md`](COMMIT_MESSAGE.md)  
  - `[type] short description [BREAK]` 형식, 타입 우선순위 정의, BREAK 규칙. (ko/en)  
  - Defines commit message format, type priorities, and `[BREAK]` convention. (en)

- 아키텍처 그림용 프롬프트: [`architecture.prompt`](images/architecture.prompt)  
  - 외부 도구(예: 나노바나나 Pro)가 참조할 상세 다이어그램 지침. (en 설명 위주)  

---

### 2.2 Server / Client Entrypoints

- 서버 메인: [`cmd/server/main.go`](cmd/server/main.go)
  - 서버 설정 로드 (`LoadServerConfigFromEnv`).
  - PostgreSQL 연결 및 ent 스키마 init (`store.OpenPostgresFromEnv`).
  - Debug 모드 시 self-signed localhost cert 생성 (`dtls.NewSelfSignedLocalhostConfig`).
  - DTLS 서버 생성 (`dtls.NewPionServer`) 및 Accept + Handshake 루프 (`PerformServerHandshake`).
  - ent 기반 `DomainValidator` + `domainGateValidator` 를 사용해 `(domain, client_api_key)` 조합과 DNS/IP(옵션) 검증을 수행.

- 클라이언트 메인: [`cmd/client/main.go`](cmd/client/main.go)  
  - CLI + env 병합 설정 (우선순위: CLI > env).  
    - `server_addr`, `domain`, `api_key`, `local_target`, `debug`.  
  - DTLS 클라이언트 생성 (`dtls.NewPionClient`)  
    - `Debug=true` 시 `InsecureSkipVerify=true` TLS 설정 사용.  
  - DTLS 핸드셰이크 수행 (`dtls.PerformClientHandshake`)  
    - 성공 시 도메인/로컬 타깃 로그 출력.  

---

### 2.3 Config / Env Handling

- 공통 설정: [`internal/config/config.go`](internal/config/config.go)  
  - `ServerConfig`  
    - `HTTPListen`, `HTTPSListen`, `DTLSListen`, `Domain`, `ProxyDomains`, `Debug`, `Logging`.  
    - env: `HOP_SERVER_HTTP_LISTEN`, `HOP_SERVER_HTTPS_LISTEN`, `HOP_SERVER_DTLS_LISTEN`, `HOP_SERVER_DOMAIN`, `HOP_SERVER_PROXY_DOMAINS`, `HOP_SERVER_DEBUG`.  
  - `ClientConfig`  
    - `ServerAddr`, `Domain`, `ClientAPIKey`, `LocalTarget`, `Debug`, `Logging`.  
    - env: `HOP_CLIENT_SERVER_ADDR`, `HOP_CLIENT_DOMAIN`, `HOP_CLIENT_API_KEY`, `HOP_CLIENT_LOCAL_TARGET`, `HOP_CLIENT_DEBUG`.  
  - `.env` 로더 (`loadDotEnvOnce`) + 각종 helper (`getEnvBool`, CSV 파싱 등).  

- DB 설정: [`internal/store/postgres.go`](internal/store/postgres.go)  
  - `ConfigFromEnv()` 로 DB 설정 로딩:  
    - `HOP_DB_DSN`, `HOP_DB_MAX_OPEN_CONNS`, `HOP_DB_MAX_IDLE_CONNS`, `HOP_DB_CONN_MAX_LIFETIME`.  

- `.env` 샘플: [`.env.example`](.env.example)  
  - Logging/Loki, 서버 포트, 클라이언트 설정, DB 설정 예시 포함.  

---

### 2.4 DTLS Layer / Handshake

- 인터페이스: [`internal/dtls/dtls.go`](internal/dtls/dtls.go)
  - `Session`, `Server`, `Client`.

- pion/dtls 전송 구현: [`internal/dtls/transport_pion.go`](internal/dtls/transport_pion.go)
  - `NewPionServer(PionServerConfig)`
    - UDP 리스너 + DTLS 서버 (`piondtls.Listen`).
  - `NewPionClient(PionClientConfig)`
    - Timeout/TLSConfig 설정, `piondtls.Dial` 사용.

- 핸드셰이크 로직: [`internal/dtls/handshake.go`](internal/dtls/handshake.go)
  - 메시지: `handshakeRequest{domain, client_api_key}`, `handshakeResponse{ok, message, domain}`.
  - `DomainValidator` 인터페이스.
  - `PerformServerHandshake` / `PerformClientHandshake` 구현 완료.

- self-signed TLS: [`internal/dtls/selfsigned.go`](internal/dtls/selfsigned.go)
  - localhost CN, SAN(DNS/IP) 포함 self-signed cert 생성.

- Domain Validator:
  - 인터페이스 정의: [`internal/dtls/handshake.go`](internal/dtls/handshake.go)
    - `ValidateDomainAPIKey(ctx, domain, clientAPIKey string) error`.
  - 실제 구현: [`internal/admin/domain_validator.go`](internal/admin/domain_validator.go)
    - ent.Client + PostgreSQL 기반으로 `Domain` 테이블 조회.
    - 도메인 문자열은 `"host"` 또는 `"host:port"` 모두 허용하되, DB 조회 시에는 host 부분만 사용.
    - `(domain, client_api_key)` 조합이 정확히 일치하는지 검증.
  - DTLS 핸드셰이크 DNS/IP 게이트: [`cmd/server/main.go`](cmd/server/main.go:37)
    - `canonicalizeDomainForDNS` + `domainGateValidator` 를 사용해, 클라이언트가 제시한 도메인의 A/AAAA 레코드가 `HOP_ACME_EXPECT_IPS` 에 설정된 IPv4/IPv6 IP 중 하나 이상과 일치하는지 검사한 뒤 DB 기반 `DomainValidator` 에 위임.
    - `HOP_ACME_EXPECT_IPS` 가 비어 있는 경우에는 DNS/IP 검증을 생략하고 DB 검증만 수행.
  - 기존 Dummy 구현: [`internal/dtls/validator_dummy.go`](internal/dtls/validator_dummy.go) 는 이제 개발/테스트용 참고 구현으로만 유지.

---

### 2.5 Admin Plane Skeleton / 관리 Plane 스켈레톤

- DomainService 인터페이스: [`internal/admin/service.go`](internal/admin/service.go)  
  - `RegisterDomain(ctx, domain, memo) (clientAPIKey string, err error)`  
  - `UnregisterDomain(ctx, domain, clientAPIKey string) error`  

- HTTP Handler: [`internal/admin/http.go`](internal/admin/http.go)
  - `Authorization: Bearer {ADMIN_API_KEY}` 검증.
  - 엔드포인트:
    - `POST /api/v1/admin/domains/register`
    - `POST /api/v1/admin/domains/unregister`
  - JSON request/response 구조 정의 및 기본 에러 처리.
  - 실제 서비스(`DomainService`) 및 라우터 wiring, ent 기반 구현이 완료되어 도메인 등록/해제가 동작.

---

### 2.6 DB / ent

- ent 스키마: [`ent/schema/domain.go`](ent/schema/domain.go)  
  - `Domain` entity:  
    - `id` (UUID, PK)  
    - `domain` (unique)  
    - `client_api_key` (unique, max 64)  
    - `memo`, `created_at`, `updated_at`.  

- ent 코드 생성 완료: [`tools/gen_ent.sh`](tools/gen_ent.sh), [`ent/*`](ent/)  
  - PostgreSQL dialect 사용.  
  - `client.Schema.Create(ctx)` 로 테이블 자동 생성(DB init).  

- PostgreSQL 연결 헬퍼: [`internal/store/postgres.go`](internal/store/postgres.go)  
  - `OpenPostgres(ctx, logger, cfg)`  
    - `ent/dialect/sql.Open("postgres", DSN)`  
    - pool 설정, ping, ent.Driver wrapping, `Schema.Create`.  
  - `OpenPostgresFromEnv(ctx, logger)`  
    - 서버에서 바로 호출 가능.  

---

### 2.7 Logging / Build / Docker

- 구조적 로깅: [`internal/logging/logging.go`](internal/logging/logging.go)
  - JSON 단일라인 로그, `level`, `ts`, `msg`, `Fields`.
  - Loki/Promtail + Grafana 스택에 최적화.

- 빌드/도커:
  - [`Makefile`](Makefile) — `make server`, `make client`, `make docker-server`.
    - `server` 타겟은 Tailwind 기반 에러 페이지 CSS 빌드를 위한 `errors-css` 타겟을 선행 실행 (`npm run build:errors-css`).
  - [`Dockerfile.server`](Dockerfile.server) — multi-stage build, Alpine runtime.
    - Build stage 에 Node.js + npm 을 설치하고, `npm install && npm run build:errors-css` 를 통해 에러 페이지용 CSS를 빌드한 뒤 Go 서버 바이너리를 생성.
  - [`.dockerignore`](.dockerignore) — `images/` 제외.

- 아키텍처 이미지: [`images/architecture.jpeg`](images/architecture.jpeg)

---

### 2.8 Error Pages / 에러 페이지

- 에러 페이지 템플릿: [`internal/errorpages/templates/*.html`](internal/errorpages/templates/400.html)
  - HTTP 상태 코드별 HTML:
    - `400.html`, `404.html`, `500.html`, `525.html`.
  - TailwindCSS 기반 레이아웃 및 스타일 적용 (영문/한글 메시지 병기).
  - `go:embed` 로 서버 바이너리에 포함되어 기본값으로 사용.

- 에러 페이지 정적 에셋: [`internal/errorpages/assets`](internal/errorpages/errorpages.go)
  - TailwindCSS 빌드 결과: `errors.css` (내장 CSS).
  - 로고 등 브랜드 리소스: `logo.svg` 등 (내장 가능).
  - 런타임에서는 `/__hopgate_assets__/...` prefix 로 HopGate 서버가 직접 서빙:
    - 1순위: `HOP_ERROR_ASSETS_DIR` 가 설정된 경우 해당 디렉터리에서 정적 파일 로드.
    - 2순위: 설정되지 않은 경우 `internal/errorpages/assets` 에 embed 된 에셋 사용.

- 에러 페이지 렌더링 로직: [`internal/errorpages/errorpages.go`](internal/errorpages/errorpages.go), [`cmd/server/main.go`](cmd/server/main.go)
  - `writeErrorPage(w, r, status)` → `errorpages.Render` 호출.
  - HTML 로딩 우선순위:
    - 1) `HOP_ERROR_PAGES_DIR/<status>.html` (env 미설정 시 `./errors/<status>.html`)
    - 2) `internal/errorpages/templates/<status>.html` (go:embed 기본 템플릿)
  - 주요 사용처:
    - 잘못된 ACME HTTP-01 요청 (400/404).
    - 허용되지 않은 Host 요청 (404).
    - DTLS 세션 부재/포워딩 실패 → 525 TLS/DTLS Handshake Failed 페이지.

---

## 3. Remaining Work / 남은 작업

### 3.1 Admin Plane Implementation / 관리 Plane 구현

- [x] DomainService 실제 구현 추가: [`internal/admin/service.go`](internal/admin/service.go)
  - ent.Client + PostgreSQL 기반 `RegisterDomain` / `UnregisterDomain` 구현.  
  - domain + client_api_key 유효성 검증 로직 포함.  

- [x] Admin API와 서버 라우터 연결: [`cmd/server/main.go`](cmd/server/main.go)
  - `http.ServeMux` 혹은 router에 `admin.Handler.RegisterRoutes` 연결.  
  - Admin API용 HTTP/HTTPS 엔드포인트 구성.  

- [x] Admin API 키 관리
  - env 혹은 설정에 `ADMIN_API_KEY` 추가 및 로딩.  
  - Admin Handler에 주입.  

---

### 3.2 DomainValidator Implementation / DomainValidator 구현

- [x] `DomainValidator` 의 실제 구현 추가 (예: `internal/admin/domain_validator.go`).
  - ent.Client 를 사용해 `Domain` 테이블 조회.
  - `(domain, client_api_key)` 조합 검증.
  - DummyDomainValidator 를 실제 구현으로 교체.

- [x] DTLS Handshake 와 Admin Plane 통합
  - Admin Plane 에서 관리하는 Domain 테이블을 사용해, 핸드셰이크 시 `(domain, client_api_key)` 조합을 DB 기준으로 검증.
  - 도메인 문자열은 `"host"` 또는 `"host:port"` 형태 모두 허용하되, DB 조회용 canonical 도메인에서는 host 부분만 사용.

---

### 3.3 Proxy Core / gRPC Tunneling

HopGate 의 최종 목표는 **TCP + TLS(HTTPS) + HTTP/2 + gRPC** 기반 터널로 HTTP 트래픽을 전달하는 것입니다.
이 섹션에서는 DTLS 기반 초기 설계를 정리만 남기고, 실제 구현/남은 작업은 gRPC 터널 기준으로 재정의합니다.

- [x] 서버 측 gRPC 터널 엔드포인트 설계/구현
  - 외부 사용자용 HTTPS(443/TCP)와 같은 포트에서:
    - 일반 HTTP 요청(브라우저/REST)은 기존 리버스 프록시 경로로,
    - `Content-Type: application/grpc` 인 요청은 클라이언트 터널용 gRPC 서버로
    라우팅하는 구조를 설계합니다.
  - 예시: `rpc OpenTunnel(stream TunnelFrame) returns (stream TunnelFrame)` (bi-directional streaming).
  - HTTP/2 + ALPN(h2)을 사용해 gRPC 스트림을 유지하고, 요청/응답 HTTP 메시지를 `TunnelFrame`으로 멀티플렉싱합니다.

- [x] 클라이언트 측 gRPC 터널 설계/구현
  - 클라이언트 프로세스는 HopGate 서버로 장기 유지 bi-di gRPC 스트림을 **하나(또는 소수 개)** 연 상태로 유지합니다.
  - 서버로부터 들어오는 `TunnelFrame`(요청 메타데이터 + 바디 chunk)을 수신해,
    로컬 HTTP 서비스(예: `127.0.0.1:8080`)로 proxy 하고, 응답을 다시 `TunnelFrame` 시퀀스로 전송합니다.
  - 기존 `internal/proxy/client.go` 의 HTTP 매핑/스트림 ARQ 경험을, gRPC 메시지 단위 chunk/flow-control 설계에 참고합니다.

- [ ] HTTP ↔ gRPC 터널 매핑 규약 정의
  - 한 HTTP 요청/응답 쌍을 gRPC 스트림 상에서 어떻게 표현할지 스키마를 정의합니다:
    - 요청: `StreamID`, method, URL, headers, body chunks
    - 응답: `StreamID`, status, headers, body chunks, error
  - 현재 `internal/protocol/protocol.go`의 논리 모델(Envelope/StreamOpen/StreamData/StreamClose/StreamAck)을
    gRPC 메시지(oneof 필드 등)로 직렬화할지, 또는 새로운 gRPC 전용 메시지를 정의할지 결정합니다.
  - Back-pressure / flow-control 은 gRPC/HTTP2의 스트림 flow-control 을 최대한 활용하고,
    추가 application-level windowing 이 필요하면 최소한으로만 도입합니다.

- [ ] gRPC 터널 기반 E2E 플로우 정의/테스트 계획
  - 하나의 gRPC 스트림 위에서:
    - 동시에 여러 정적 리소스(`/css`, `/js`, `/img`) 요청,
    - 큰 응답(수 MB 파일)과 작은 응답(API JSON)이 섞여 있는 시나리오,
    - 클라이언트 재시작/네트워크 단절 후 재연결 시나리오
    를 포함하는 테스트 플랜을 작성합니다.
  - 기대 동작:
    - 느린 요청이 있더라도 다른 요청이 **같은 TCP 연결/스트림 집합 내에서** 과도하게 지연되지 않을 것.
    - 서버/클라이언트 로그에 프로토콜 위반 경고(`unexpected frame ...`)가 발생하지 않을 것.

> Note: 기존 DTLS 기반 스트림/ARQ/멀티플렉싱(3.3A/3.3B)의 작업 내역은
> 구현 경험/아이디어 참고용으로만 유지하며, 신규 기능/운영 계획은 gRPC 터널을 기준으로 진행합니다.

---

### 3.4 ACME Integration / ACME 연동

- [x] [`internal/acme/acme.go`](internal/acme/acme.go) 실제 구현
  - lego 기반 ACME 매니저 구현.
  - 메인 도메인 + 프록시 도메인용 인증서 발급/갱신.
  - HTTP-01 챌린지 처리(webroot 방식).

- [x] 서버 main 에 ACME 기반 `*tls.Config` 주입
  - DTLS / HTTPS 리스너에 ACME 인증서 적용 (Debug 모드에서는 DTLS 에 self-signed, HTTPS 에 ACME 사용).

- [ ] ACME 고급 기능 및 운영 전략 보완
  - TLS-ALPN-01 챌린지 지원 여부 검토 및 필요 시 lego 설정/핸들러 추가.
  - 인증서 발급/갱신 실패 시 재시도/백오프 및 경고 로그/알림을 포함한 에러 처리 전략 정의.
  - Debug(스테이징 CA) / Production(실 CA) 환경 전환 플로우와 도메인/환경별 ACME 설정 매트릭스를 문서화.

---

### 3.5 Observability / 관측성

- [x] Prometheus 메트릭 노출 및 서버 wiring
  - `cmd/server/main.go` 에 Prometheus `/metrics` 엔드포인트 추가 (예: promhttp.Handler).
  - DTLS 핸드셰이크 성공/실패 수, HTTP 요청 수, HTTP 요청 지연, Proxy 에러 수에 대한 메트릭을 정의합니다.
  - 메트릭 라벨은 메서드/상태 코드/결과/에러 타입 등에 한정되며, 도메인/클라이언트 ID/request_id 는 구조적 로그 필드로만 노출됩니다.

- [ ] Loki/Grafana 대시보드 및 쿼리 예시
  - Loki/Promtail 구성을 가정한 주요 로그 쿼리 예시 정리(도메인, 클라이언트 ID, request_id 기준).
  - Prometheus 메트릭 기반 기본 대시보드 템플릿 작성 (DTLS 상태, 프록시 트래픽, 에러율 등).

---

### 3.6 Hardening / 안정성 & 구성

- [x] 설정 유효성 검사 추가
  - 필수 env 누락/오류에 대한 명확한 에러 메시지.

- [ ] 에러 처리/재시도 정책
  - DTLS 재연결, Proxy 재시도, DB 재시도 정책 정의.

- [ ] 보안 검토
  - Admin API 인증 방식 재검토 (예: IP allowlist, 추가 인증 수단).
  - 클라이언트 API Key 저장/회전 전략.

- [ ] Proxy 서버 추상화 및 Router 리팩터링
  - `internal/proxy/server.go` 의 `ServerProxy` 및 `Router` 인터페이스를 실제 HTTP ↔ DTLS 터널링 경로에 적용.
  - 현재 `cmd/server/main.go` 에 위치한 Proxy 코어 로직을 proxy 레이어로 이동.

---

## 4. Milestones / 마일스톤

### Milestone 1 — DTLS Handshake + Admin + DB (기본 인증 토대)

- [x] DTLS transport & handshake skeleton 구현 (server/client).
- [x] Domain ent schema + PostgreSQL 연결 & schema init.
- [x] DomainService 실제 구현 + DomainValidator 구현.
- [x] Admin API + ent + PostgreSQL 연결 (실제 도메인 등록/해제 동작).

### Milestone 2 — Full HTTP Tunneling (프락시 동작 완성)

- [x] 서버 Proxy 코어 구현 및 HTTPS ↔ DTLS 라우팅.
  - 현재 `cmd/server/main.go` 의 `newHTTPHandler` / `dtlsSessionWrapper.ForwardHTTP` 경로에서 동작합니다.
- [x] 클라이언트 Proxy 루프 구현 및 로컬 서비스 연동.
  - `cmd/client/main.go` + [`ClientProxy.StartLoop()`](internal/proxy/client.go:59) 를 통해 DTLS 세션 위에서 로컬 서비스와 연동됩니다.
- [ ] End-to-end HTTP 요청/응답 터널링 E2E 테스트.

### Milestone 3 — ACME + TLS/DTLS 정식 인증

- [x] ACME 매니저 구현 (lego 기반).
- [x] HTTPS/DTLS 리스너에 ACME 인증서 주입.
- [ ] ACME 고급 기능 및 운영 전략 정리 (예: TLS-ALPN-01, 인증서 롤오버/장애 대응 전략).

### Milestone 4 — Observability & Hardening

- [ ] Prometheus/Loki/Grafana 통합.
  - Prometheus 메트릭 정의 및 `/metrics` 엔드포인트는 이미 구현 및 동작 중이며,
    Loki/Promtail/Grafana 대시보드 및 운영 통합 작업은 아직 남아 있습니다.

- [ ] 에러/리트라이/타임아웃 정책 정교화.  
- [ ] 보안/구성 최종 점검 및 문서화.  

---

이 `progress.md` 파일은 아키텍처/코드 변경에 따라 수시로 업데이트하며, Milestone 기준으로 완료 여부를 체크해 나가면 된다.  
This `progress.md` file should be updated as the architecture and code evolve, using the milestones above as a checklist.