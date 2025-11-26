# HopGate Progress / 진행 현황

이 문서는 HopGate 아키텍처 대비 현재 구현 상태와 이후 추가해야 할 작업을 정리한 Milestone 문서입니다. (ko)  
This document tracks implementation progress against the HopGate architecture and lists remaining milestones. (en)

---

## 1. High-level Status / 상위 수준 상태

- 아키텍처 문서 및 README 정리 완료 (ko/en 병기).  
  Architecture and README are documented in both Korean and English.  
- 서버/클라이언트 엔트리 포인트, DTLS 핸드셰이크, 기본 PostgreSQL/ent 스키마까지 1차 뼈대 구현 완료.  
  First skeleton implementation is done for server/client entrypoints, DTLS handshake, and basic PostgreSQL/ent schema.  
- 실제 Proxy 동작(HTTP ↔ DTLS 터널링), Admin API의 비즈니스 로직, 실 ACME 연동 등은 아직 남아 있음.  
  Actual proxying (HTTP ↔ DTLS tunneling), admin API business logic, and real ACME integration are still pending.  

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

- 아키텍처 그림용 프롬프트: [`arkitecture.prompt`](arkitecture.prompt)  
  - 외부 도구(예: 나노바나나 Pro)가 참조할 상세 다이어그램 지침. (en 설명 위주)  

---

### 2.2 Server / Client Entrypoints

- 서버 메인: [`cmd/server/main.go`](cmd/server/main.go)  
  - 서버 설정 로드 (`LoadServerConfigFromEnv`).  
  - PostgreSQL 연결 및 ent 스키마 init (`store.OpenPostgresFromEnv`).  
  - Debug 모드 시 self-signed localhost cert 생성 (`dtls.NewSelfSignedLocalhostConfig`).  
  - DTLS 서버 생성 (`dtls.NewPionServer`) 및 Accept + Handshake 루프 (`PerformServerHandshake`).  
  - DummyDomainValidator 사용해 도메인/API Key 조합을 임시로 모두 허용.  

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

- Dummy Validator: [`internal/dtls/validator_dummy.go`](internal/dtls/validator_dummy.go)  
  - 현재 모든 도메인/API Key 조합을 허용하며, 마스킹된 키와 함께 디버그 로그 출력.  

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
  - 아직 실제 서비스/라우터 wiring, ent 기반 구현 미완성.  

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
  - [`Dockerfile.server`](Dockerfile.server) — multi-stage build, Alpine runtime.  
  - [`.dockerignore`](.dockerignore) — `images/` 제외.  

- 아키텍처 이미지: [`images/architecture.jpeg`](images/architecture.jpeg)  

---

## 3. Remaining Work / 남은 작업

### 3.1 Admin Plane Implementation / 관리 Plane 구현

- [ ] DomainService 실제 구현 추가: [`internal/admin/service.go`](internal/admin/service.go)  
  - ent.Client + PostgreSQL 기반 `RegisterDomain` / `UnregisterDomain` 구현.  
  - domain + client_api_key 유효성 검증 로직 포함.  

- [ ] Admin API와 서버 라우터 연결: [`cmd/server/main.go`](cmd/server/main.go)  
  - `http.ServeMux` 혹은 router에 `admin.Handler.RegisterRoutes` 연결.  
  - Admin API용 HTTP/HTTPS 엔드포인트 구성.  

- [ ] Admin API 키 관리  
  - env 혹은 설정에 `ADMIN_API_KEY` 추가 및 로딩.  
  - Admin Handler에 주입.  

---

### 3.2 DomainValidator Implementation / DomainValidator 구현

- [ ] `DomainValidator` 의 실제 구현 추가 (예: `internal/admin/domain_validator.go`).  
  - ent.Client 를 사용해 `Domain` 테이블 조회.  
  - `(domain, client_api_key)` 조합 검증.  
  - DummyDomainValidator 를 실제 구현으로 교체.  

- [ ] DTLS Handshake 와 Admin Plane 통합  
  - Domain 등록/해제가 handshake 검증 로직에 반영되도록 설계.  

---

### 3.3 Proxy Core / HTTP Tunneling

- [ ] 서버 측 Proxy 구현 확장: [`internal/proxy/server.go`](internal/proxy/server.go)  
  - HTTP/HTTPS 리스너와 DTLS 세션 매핑 구현.  
  - `Router` 구현체 추가 (도메인/패스 → 클라이언트/서비스).  
  - 요청/응답을 `internal/protocol` 구조체로 직렬화/역직렬화.  

- [ ] 클라이언트 측 Proxy 구현 확장: [`internal/proxy/client.go`](internal/proxy/client.go)  
  - DTLS 세션에서 `protocol.Request` 수신 → 로컬 HTTP 호출 → `protocol.Response` 전송 루프 구현.  
  - timeout/취소/에러 처리.  

- [ ] 서버 main 에 Proxy wiring 추가: [`cmd/server/main.go`](cmd/server/main.go)  
  - DTLS handshake 완료된 세션을 Proxy 라우팅 테이블에 등록.  
  - HTTPS 서버와 Proxy 핸들러 연결.  

- [ ] 클라이언트 main 에 Proxy loop wiring 추가: [`cmd/client/main.go`](cmd/client/main.go)  
  - handshake 성공 후 `proxy.ClientProxy.StartLoop` 실행.  

---

### 3.4 ACME Integration / ACME 연동

- [ ] [`internal/acme/acme.go`](internal/acme/acme.go) 실제 구현  
  - certmagic 또는 lego 기반 ACME 매니저 구현.  
  - 메인 도메인 + 프록시 도메인용 인증서 발급/갱신.  
  - HTTP-01/TLS-ALPN-01 챌린지 처리.  

- [ ] 서버 main 에 ACME 기반 `*tls.Config` 주입  
  - DTLS / HTTPS 리스너에 ACME 인증서 적용 (Debug 모드 예외).  

---

### 3.5 Observability / 관측성

- [ ] Prometheus 메트릭 노출  
  - `/metrics` 엔드포인트 추가.  
  - DTLS 세션 수, 요청 수, 에러 수 등 카운터/게이지 정의.  

- [ ] Loki/Grafana 대시보드 템플릿 초안 작성  
  - 주요 필터(도메인, 클라이언트 ID, request_id) 기준 쿼리 예시.  

---

### 3.6 Hardening / 안정성 & 구성

- [ ] 설정 유효성 검사 추가  
  - 필수 env 누락/오류에 대한 명확한 에러 메시지.  

- [ ] 에러 처리/재시도 정책  
  - DTLS 재연결, Proxy 재시도, DB 재시도 정책 정의.  

- [ ] 보안 검토  
  - Admin API 인증 방식 재검토 (예: IP allowlist, 추가 인증 수단).  
  - 클라이언트 API Key 저장/회전 전략.  

---

## 4. Milestones / 마일스톤

### Milestone 1 — DTLS Handshake + Admin + DB (기본 인증 토대)

- [x] DTLS transport & handshake skeleton 구현 (server/client).  
- [x] Domain ent schema + PostgreSQL 연결 & schema init.  
- [ ] DomainService 실제 구현 + DomainValidator 구현.  
- [ ] Admin API + ent + PostgreSQL 연결 (실제 도메인 등록/해제 동작).  

### Milestone 2 — Full HTTP Tunneling (프락시 동작 완성)

- [ ] 서버 Proxy 코어 구현 및 HTTPS ↔ DTLS 라우팅.  
- [ ] 클라이언트 Proxy 루프 구현 및 로컬 서비스 연동.  
- [ ] End-to-end HTTP 요청/응답 터널링 E2E 테스트.  

### Milestone 3 — ACME + TLS/DTLS 정식 인증

- [ ] ACME 매니저 구현 (certmagic/lego).  
- [ ] HTTPS/DTLS 리스너에 ACME 인증서 주입.  
- [ ] Debug 모드(self-signed)와 Production 모드(ACME) 전환 전략 정리.  

### Milestone 4 — Observability & Hardening

- [ ] Prometheus/Loki/Grafana 통합.  
- [ ] 에러/리트라이/타임아웃 정책 정교화.  
- [ ] 보안/구성 최종 점검 및 문서화.  

---

이 `progress.md` 파일은 아키텍처/코드 변경에 따라 수시로 업데이트하며, Milestone 기준으로 완료 여부를 체크해 나가면 된다.  
This `progress.md` file should be updated as the architecture and code evolve, using the milestones above as a checklist.