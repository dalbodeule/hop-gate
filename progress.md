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

### 3.3 Proxy Core / HTTP Tunneling

- [ ] 서버 측 Proxy 구현 확장: [`internal/proxy/server.go`](internal/proxy/server.go)
  - 현재 `ServerProxy` / `Router` 인터페이스와 `NewHTTPServer` 만 정의되어 있고,
    실제 HTTP/HTTPS 리스너와 DTLS 세션 매핑 로직은 [`cmd/server/main.go`](cmd/server/main.go) 의
    `newHTTPHandler` / `dtlsSessionWrapper.ForwardHTTP` 안에 위치합니다.
  - Proxy 코어 로직을 proxy 레이어로 이동하는 리팩터링은 아직 진행되지 않았습니다. (3.6 항목과 연동)

- [x] 클라이언트 측 Proxy 구현 확장: [`internal/proxy/client.go`](internal/proxy/client.go)
  - DTLS 세션에서 `protocol.Request` 수신 → 로컬 HTTP 호출 → `protocol.Response` 전송 루프 구현.
  - timeout/취소/에러 처리.

- [x] 서버 main 에 Proxy wiring 추가: [`cmd/server/main.go`](cmd/server/main.go)
  - DTLS handshake 완료된 세션을 Proxy 라우팅 테이블에 등록.
  - HTTPS 서버와 Proxy 핸들러 연결.

- [x] 클라이언트 main 에 Proxy loop wiring 추가: [`cmd/client/main.go`](cmd/client/main.go)
  - handshake 성공 후 `proxy.ClientProxy.StartLoop` 실행.

#### 3.3A Stream-based DTLS Tunneling / 스트림 기반 DTLS 터널링

초기 HTTP 터널링 설계는 **단일 JSON Envelope + 단일 DTLS 쓰기** 방식(요청/응답 바디 전체를 한 번에 전송)이었고,
대용량 응답 바디에서 UDP MTU 한계로 인한 `sendto: message too long` 문제가 발생할 수 있었습니다.
이 한계를 제거하기 위해, 현재 코드는 DTLS 위 애플리케이션 프로토콜을 **스트림/프레임 기반**으로 재설계하여 `StreamOpen` / `StreamData` / `StreamClose` 를 사용합니다.
The initial tunneling model used a **single JSON envelope + single DTLS write per HTTP message**, which could hit UDP MTU limits (`sendto: message too long`) for large bodies.
The current implementation uses a **stream/frame-based** protocol over DTLS (`StreamOpen` / `StreamData` / `StreamClose`), and this section documents its constraints and further improvements (e.g. ARQ).

고려해야 할 제약 / Constraints:

- 전송 계층은 DTLS(pion/dtls)를 유지합니다.
  The transport layer must remain DTLS (pion/dtls).
- JSON 기반 단일 Envelope 모델에서 벗어나, HTTP 바디를 안전한 크기의 chunk 로 나누어 전송해야 합니다.
  We must move away from the single-envelope JSON model and chunk HTTP bodies under a safe MTU.
- UDP 특성상 일부 프레임 손실/오염에 대비해, **해당 chunk 만 재전송 요청할 수 있는 ARQ 메커니즘**이 필요합니다.
  Given UDP characteristics, we need an application-level ARQ so that **only lost/corrupted chunks are retransmitted**.

아래 단계들은 `feature/udp-stream` 브랜치에서 구현할 구체적인 작업 항목입니다.
The following tasks describe concrete work items to be implemented on the `feature/udp-stream` branch.

---

##### 3.3A.1 스트림 프레이밍 프로토콜 설계 (JSON 1단계)
##### 3.3A.1 Stream framing protocol (JSON, phase 1)

- [x] 스트림 프레임 타입 정리 및 확장: [`internal/protocol/protocol.go`](internal/protocol/protocol.go:35)
  - 이미 정의된 스트림 관련 타입을 1단계에서 적극 활용합니다.
    Reuse the already defined stream-related types in phase 1:
    - `MessageTypeStreamOpen`, `MessageTypeStreamData`, `MessageTypeStreamClose`
    - [`Envelope`](internal/protocol/protocol.go:52), [`StreamOpen`](internal/protocol/protocol.go:69), [`StreamData`](internal/protocol/protocol.go:80), [`StreamClose`](internal/protocol/protocol.go:86)
  - `StreamData` 에 per-stream 시퀀스 번호를 추가합니다.
    Add a per-stream sequence number to `StreamData`:
    - 예시 / Example:
      ```go
      type StreamData struct {
      	ID   StreamID `json:"id"`
      	Seq  uint64   `json:"seq"`  // 0부터 시작하는 per-stream sequence
      	Data []byte   `json:"data"`
      }
      ```

- [x] 스트림 ACK / 재전송 제어 메시지 추가: [`internal/protocol/protocol.go`](internal/protocol/protocol.go:52)
  - 선택적 재전송(Selective Retransmission)을 위해 `StreamAck` 메시지와 `MessageTypeStreamAck` 를 추가합니다.
    Add `StreamAck` message and `MessageTypeStreamAck` for selective retransmission:
    ```go
    const (
    	MessageTypeStreamAck MessageType = "stream_ack"
    )

    type StreamAck struct {
    	ID         StreamID `json:"id"`              // 대상 스트림 / target stream
    	AckSeq     uint64   `json:"ack_seq"`        // 연속으로 수신 완료한 마지막 Seq / last contiguous sequence
    	LostSeqs   []uint64 `json:"lost_seqs"`      // 누락된 시퀀스 목록(선택) / optional list of missing seqs
    	WindowSize uint32   `json:"window_size"`    // 선택: 허용 in-flight 프레임 수 / optional receive window
    }
    ```
  - [`Envelope`](internal/protocol/protocol.go:52)에 `StreamAck *StreamAck` 필드를 추가합니다.
    Extend `Envelope` with a `StreamAck *StreamAck` field.

- [x] MTU-safe chunk 크기 정의
	- DTLS/UDP 헤더 및 Protobuf/length-prefix 오버헤드를 고려해 안전한 payload 크기(4KiB)를 상수로 정의합니다.
		Define a safe payload size constant (4KiB) considering DTLS/UDP headers and Protobuf/length-prefix framing.
	- 이 값은 [`internal/protocol/protocol.go`](internal/protocol/protocol.go:32) 의 `StreamChunkSize` 로 정의되었습니다.
		Implemented as `StreamChunkSize` in [`internal/protocol/protocol.go`](internal/protocol/protocol.go:32).
	- 이후 HTTP 바디 스트림 터널링 구현 시, 모든 `StreamData.Data` 는 이 크기 이하 chunk 로 잘라 전송해야 합니다.
		In the stream tunneling implementation, every `StreamData.Data` must be sliced into chunks no larger than this size.

---

##### 3.3A.2 애플리케이션 레벨 ARQ 설계 (Selective Retransmission)
##### 3.3A.2 Application-level ARQ (Selective Retransmission)

- [x] 수신 측 ARQ 상태 관리 구현
  - 스트림별로 `expectedSeq`, out-of-order chunk 버퍼(`received`), 누락 시퀀스 집합(`lost`)을 유지하면서,
    in-order / out-of-order 프레임을 구분해 HTTP 바디 버퍼에 순서대로 쌓습니다.
  - For each stream, maintain `expectedSeq`, an out-of-order buffer (`received`), and a lost-sequence set (`lost`),
    delivering in-order frames directly to the HTTP body buffer while buffering/reordering out-of-order ones.

- [x] 수신 측 StreamAck 전송 정책 구현
  - 각 `StreamData` 수신 시점에 `AckSeq = expectedSeq - 1` 과 현재 윈도우에서 누락된 시퀀스 일부(`LostSeqs`, 상한 개수 적용)를 포함한
    `StreamAck{AckSeq, LostSeqs}` 를 전송해 선택적 재전송을 유도합니다.
  - On every `StreamData` frame, send `StreamAck{AckSeq, LostSeqs}` where `AckSeq = expectedSeq - 1` and `LostSeqs`
    contains a bounded set (up to a fixed limit) of missing sequence numbers in the current receive window.

- [x] 송신 측 재전송 로직 구현 (StreamAck 기반)
  - 응답 스트림 송신 측에서 스트림별 `streamSender` 를 두고, `outstanding[seq] = payload` 로 아직 Ack 되지 않은 프레임을 추적합니다.
  - `StreamAck{AckSeq, LostSeqs}` 수신 시:
    - `seq <= AckSeq` 인 항목은 모두 제거하고,
    - `LostSeqs` 에 포함된 시퀀스에 대해서만 `StreamData{ID, Seq, Data}` 를 재전송합니다.
  - A per-stream `streamSender` tracks `outstanding[seq] = payload` for unacknowledged frames. Upon receiving
    `StreamAck{AckSeq, LostSeqs}`, it deletes all `seq <= AckSeq` and retransmits only frames whose sequence
    numbers appear in `LostSeqs`.

> Note: 현재 구현은 StreamAck 기반 **선택적 재전송(Selective Retransmission)** 까지 포함하며,
> 별도의 RTO(재전송 타이머) 기반 백그라운드 재전송 루프는 향후 확장 여지로 남겨둔 상태입니다.
> Note: The current implementation covers StreamAck-based **selective retransmission**; a separate RTO-based
> background retransmission loop is left as a potential future enhancement.

---

##### 3.3A.3 HTTP ↔ 스트림 매핑 (서버/클라이언트)
##### 3.3A.3 HTTP ↔ stream mapping (server/client)

- [x] 서버 → 클라이언트 요청 스트림: [`cmd/server/main.go`](cmd/server/main.go:200)
  - `ForwardHTTP` 는 스트림 기반 HTTP 요청/응답을 처리하도록 구현되어 있으며, 동작은 다음과 같습니다.
    `ForwardHTTP` is implemented in stream mode and behaves as follows:
    - HTTP 요청 수신 시:
      - 새로운 `StreamID` 를 발급합니다 (세션별 증가).
        Generate a new `StreamID` per incoming HTTP request on the DTLS session.
      - `StreamOpen` 전송:
        - 요청 메서드/URL/헤더를 [`StreamOpen`](internal/protocol/protocol.go:69) 의 `Header` 혹은 pseudo-header 로 encode.
          Encode method/URL/headers into `StreamOpen.Header` or a pseudo-header scheme.
      - 요청 바디를 읽으면서 `StreamData{ID, Seq, Data}` 를 지속적으로 전송합니다.
        Read the HTTP request body and send it as a sequence of `StreamData` frames.
      - 바디 종료 시 `StreamClose{ID, Error:""}` 를 전송합니다.
        When the body ends, send `StreamClose{ID, Error:""}`.
    - 응답 수신:
      - 클라이언트에서 오는 역방향 `StreamOpen` 으로 HTTP status/header 를 수신하고,
        이를 `http.ResponseWriter` 에 반영합니다.
        Receive response status/headers via reverse-direction `StreamOpen` and map them to `http.ResponseWriter`.
      - 연속되는 `StreamData` 를 수신할 때마다 `http.ResponseWriter.Write` 로 chunk 를 바로 전송합니다.
        For each `StreamData`, write the chunk directly to the HTTP response.
      - `StreamClose` 수신 시 응답 종료 및 스트림 자원 정리.
        On `StreamClose`, finish the response and clean up per-stream state.

- [x] 클라이언트에서의 요청 처리 스트림: [`internal/proxy/client.go`](internal/proxy/client.go:200)
  - 서버로부터 들어오는 `StreamOpen{ID, ...}` 을 수신하면,
    새로운 goroutine 을 띄워 해당 ID에 대한 로컬 HTTP 요청을 수행합니다.
    On receiving `StreamOpen{ID, ...}` from the server, spawn a goroutine to handle the local HTTP request for that stream ID.
  - 스트림별로 `io.Pipe` 또는 채널 기반 바디 리더를 준비하고,
    `StreamData` 프레임을 수신할 때마다 이 파이프에 쓰도록 합니다.
    Prepare an `io.Pipe` (or channel-backed reader) per stream and write incoming `StreamData` chunks into it.
  - 로컬 HTTP 클라이언트 응답은 반대로:
    For the local HTTP client response:
    - 응답 status/header → `StreamOpen` (client → server)
    - 응답 바디 → 여러 개의 `StreamData`
    - 종료 시점에 `StreamClose` 전송
      Send `StreamOpen` (status/headers), then a sequence of `StreamData`, followed by `StreamClose` when done.

---

##### 3.3A.4 JSON → 바이너리 직렬화로의 잠재적 전환 (2단계)
##### 3.3A.4 JSON → binary serialization (potential phase 2)

- [x] JSON 기반 스트림 프로토콜의 1단계 구현/안정화 이후, 직렬화 포맷 재검토 및 Protobuf 전환
  - 현재는 JSON 대신 Protobuf length-prefix `Envelope` 포맷을 기본으로 사용합니다.
    The runtime now uses a Protobuf-based, length-prefixed `Envelope` format instead of JSON.
  - HTTP/스트림 payload 는 여전히 MTU-safe 크기(예: 4KiB, `StreamChunkSize`)로 제한되어 있어, 단일 프레임이 과도하게 커지지 않습니다.
    HTTP/stream payloads remain bounded to an MTU-safe size (e.g. 4KiB via `StreamChunkSize`), so individual frames stay small.
- [x] length-prefix 이진 프레임(Protobuf)으로 전환
  - 동일한 logical model (`StreamOpen` / `StreamData(seq)` / `StreamClose` / `StreamAck`)을 유지한 채,
    wire-format 을 Protobuf length-prefix binary 프레이밍으로 교체했고, 이는 `protobufCodec` 으로 구현되었습니다.
    We now keep the same logical model while using Protobuf length-prefixed framing via `protobufCodec`.
- [x] 이 전환은 `internal/protocol` 내 직렬화 레이어를 얇은 abstraction 으로 감싸 구현했습니다.
  - [`internal/protocol/codec.go`](internal/protocol/codec.go:130) 에 `WireCodec` 인터페이스와 Protobuf 기반 `DefaultCodec` 을 도입해,
    호출자는 `protocol.DefaultCodec` 만 사용하고, JSON codec 은 보조 용도로만 남아 있습니다.
    In [`internal/protocol/codec.go`](internal/protocol/codec.go:130), the `WireCodec` abstraction and Protobuf-based `DefaultCodec` allow callers to use only `protocol.DefaultCodec` while JSON remains as an auxiliary codec.

---
 
##### 3.3B DTLS Session Multiplexing / 세션 내 다중 HTTP 요청 처리

현재 구현은 클라이언트 측에서 단일 DTLS 세션 내에 **동시에 하나의 HTTP 요청 스트림만** 처리할 수 있습니다.
`ClientProxy.handleStreamRequest` 가 DTLS 세션의 reader 를 직접 소비하기 때문에, 동일 세션에서 두 번째 `StreamOpen` 이 섞여 들어오면 프로토콜 위반으로 간주되고 세션이 끊어집니다.
이 섹션은 **클라이언트 측 스트림 demux + per-stream goroutine 구조**를 도입해, 하나의 DTLS 세션 안에서 여러 HTTP 요청을 안전하게 병렬 처리하기 위한 단계입니다.

Currently, the client can effectively handle **only one HTTP request stream at a time per DTLS session**.
Because `ClientProxy.handleStreamRequest` directly consumes the DTLS session reader, an additional `StreamOpen` for a different stream interleaving on the same session is treated as a protocol error and tears down the session.
This section introduces a **client-side stream demultiplexer + per-stream goroutines** to safely support multiple concurrent HTTP requests within a single DTLS session.

---

##### 3.3B.1 클라이언트 측 중앙 readLoop → 스트림 demux 설계
##### 3.3B.1 Design client-side central readLoop → per-stream demux

- [x] `ClientProxy.StartLoop` 의 역할을 명확히 분리
  - DTLS 세션에서 `Envelope` 를 연속해서 읽어들이는 **중앙 readLoop** 를 유지하되,
  - 개별 스트림의 HTTP 처리 로직(현재 `handleStreamRequest` 내부 로직)을 분리해 별도 타입/구조체로 옮길 계획을 문서화합니다.
- [x] 스트림 demux 위한 자료구조 설계
  - `map[protocol.StreamID]*streamReceiver` 형태의 수신측 스트림 상태 테이블을 정의합니다.
  - 각 `streamReceiver` 는 자신만의 입력 채널(예: `inCh chan *protocol.Envelope`)을 가져, 중앙 readLoop 로부터 `StreamOpen/StreamData/StreamClose` 를 전달받도록 합니다.
- [x] 중앙 readLoop 에서 스트림별 라우팅 규칙 정의
  - `Envelope.Type` 에 따라:
    - `StreamOpen` / `StreamData` / `StreamClose`:
      - `streamID` 를 추출하고, 해당 `streamReceiver` 의 `inCh` 로 전달.
      - `StreamOpen` 수신 시에는 아직 없는 경우 `streamReceiver` 를 생성 후 등록.
    - `StreamAck`:
      - 송신 측 ARQ(`streamSender`) 용 테이블(이미 구현된 구조)을 찾아 재전송 로직으로 전달.
  - 이 설계를 통해 중앙 readLoop 는 **DTLS 세션 → 스트림 단위 이벤트 분배**만 담당하도록 제한합니다.

---

##### 3.3B.2 streamReceiver 타입 설계 및 HTTP 매핑 리팩터링
##### 3.3B.2 Design streamReceiver type and refactor HTTP mapping

- [x] `streamReceiver` 타입 정의
  - 필드 예시:
    - `id protocol.StreamID`
    - 수신 ARQ 상태: `expectedSeq`, `received map[uint64][]byte`, `lost map[uint64]struct{}`
    - 입력 채널: `inCh chan *protocol.Envelope`
    - DTLS 세션/codec/logging 핸들: `sess dtls.Session`, `codec protocol.WireCodec`, `logger logging.Logger`
    - 로컬 HTTP 호출 관련: `HTTPClient *http.Client`, `LocalTarget string`
  - 역할:
    - 서버에서 온 `StreamOpen`/`StreamData`/`StreamClose` 를 순서대로 처리해 로컬 HTTP 요청을 구성하고,
    - 로컬 HTTP 응답을 다시 `StreamOpen`/`StreamData`/`StreamClose` 로 역방향 전송합니다.
- [x] 기존 `ClientProxy.handleStreamRequest` 의 로직을 `streamReceiver` 로 이전
  - 현재 `handleStreamRequest` 안에서 수행하던 작업을 단계적으로 옮깁니다:
    - `StreamOpen` 의 pseudo-header 에서 HTTP 메서드/URL/헤더를 복원.
    - 요청 바디 수신용 수신 측 ARQ(`expectedSeq`, `received`, `lost`) 처리.
    - 로컬 HTTP 요청 생성/실행 및 에러 처리.
    - 응답을 4KiB `StreamData` chunk 로 전송 + 송신 측 ARQ(`streamSender.register`) 기록.
  - 이때 **DTLS reader 를 직접 읽던 부분**은 제거하고, 대신 `inCh` 에서 전달된 `Envelope` 만 사용하도록 리팩터링합니다.
- [x] streamReceiver 생명주기 관리
  - `StreamClose` 수신 시:
    - 로컬 HTTP 요청 바디 구성 종료.
    - 로컬 HTTP 요청 실행 및 응답 스트림 전송 완료 후,
    - `streamReceivers[streamID]` 에서 자신을 제거하고 goroutine 을 종료하는 정책을 명확히 정의합니다.

---

##### 3.3B.3 StartLoop 와 streamReceiver 통합
##### 3.3B.3 Integrate StartLoop and streamReceiver

- [x] `ClientProxy.StartLoop` 을 “중앙 readLoop + demux” 로 단순화
  - `MessageTypeStreamOpen` 수신 시:
    - `streamID := env.StreamOpen.ID` 를 기준으로 기존 `streamReceiver` 존재 여부를 검사.
    - 없으면 새 `streamReceiver` 생성 후, goroutine 을 띄우고 `inCh <- env` 로 첫 메시지 전달.
  - `MessageTypeStreamData` / `MessageTypeStreamClose` 수신 시:
    - 해당 `streamReceiver` 의 `inCh` 로 그대로 전달.
  - `MessageTypeStreamAck` 는 기존처럼 송신 측 `streamSender` 로 라우팅.
- [x] 에러/종료 처리 전략 정리
  - 개별 `streamReceiver` 에서 발생하는 에러는:
    - 로컬 HTTP 에러 → 스트림 응답에 5xx/에러 바디로 반영.
    - 프로토콜 위반(예: 잘못된 순서의 `StreamClose`) → 해당 스트림만 정리하고 세션은 유지하는지 여부를 정의.
  - DTLS 세션 레벨 에러(EOF, decode 실패 등)는:
    - 모든 `streamReceiver` 의 `inCh` 를 닫고,
    - 이후 클라이언트 전체 루프를 종료하는 방향으로 합의합니다.

---

##### 3.3B.4 세션 단위 직렬화 락 제거 및 멀티플렉싱 검증
##### 3.3B.4 Remove session-level serialization lock and validate multiplexing

- [x] 서버 측 세션 직렬화 락 제거 계획 수립
  - 현재 서버는 [`dtlsSessionWrapper`](cmd/server/main.go:111)에 `requestMu` 를 두어,
    - 동일 DTLS 세션에서 동시에 하나의 `ForwardHTTP` 만 수행하도록 직렬화하고 있습니다.
  - 클라이언트 측 멀티플렉싱이 안정화되면, `requestMu` 를 제거하고
    - 하나의 세션 안에서 여러 HTTP 요청이 각기 다른 `StreamID` 로 병렬 진행되도록 허용합니다.
- [ ] E2E 멀티플렉싱 테스트 시나리오 정의
  - 하나의 DTLS 세션 위에서:
    - 동시에 여러 정적 리소스(`/css`, `/js`, `/img`) 요청.
    - 큰 응답(수 MB 파일)과 작은 응답(API JSON)이 섞여 있는 시나리오.
  - 기대 동작:
    - 어떤 요청이 느리더라도, 다른 요청이 세션 내부 큐잉 때문에 과도하게 지연되지 않고 병렬로 완료되는지 확인.
    - 클라이언트/서버 로그에 프로토콜 위반(`unexpected envelope type ...`) 이 더 이상 발생하지 않는지 확인.
- [ ] 관측성/메트릭에 멀티플렉싱 관련 라벨/필드 추가(선택)
  - 필요 시:
    - 세션당 동시 활성 스트림 수,
    - 스트림 수명(요청-응답 왕복 시간),
    - 세션 내 스트림 에러 수
    를 관찰할 수 있는 메트릭/로그 필드를 설계합니다.

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

- [ ] 설정 유효성 검사 추가
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