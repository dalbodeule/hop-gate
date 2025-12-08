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

- 아키텍처 그림용 프롬프트: [`architecture.prompt`](images/architecture.prompt)  
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

- [x] 서버 측 Proxy 구현 확장: [`internal/proxy/server.go`](internal/proxy/server.go)
  - HTTP/HTTPS 리스너와 DTLS 세션 매핑 구현.
  - `Router` 구현체 추가 (도메인/패스 → 클라이언트/서비스).
  - 요청/응답을 `internal/protocol` 구조체로 직렬화/역직렬화.

- [x] 클라이언트 측 Proxy 구현 확장: [`internal/proxy/client.go`](internal/proxy/client.go)
  - DTLS 세션에서 `protocol.Request` 수신 → 로컬 HTTP 호출 → `protocol.Response` 전송 루프 구현.
  - timeout/취소/에러 처리.

- [x] 서버 main 에 Proxy wiring 추가: [`cmd/server/main.go`](cmd/server/main.go)
  - DTLS handshake 완료된 세션을 Proxy 라우팅 테이블에 등록.
  - HTTPS 서버와 Proxy 핸들러 연결.

- [x] 클라이언트 main 에 Proxy loop wiring 추가: [`cmd/client/main.go`](cmd/client/main.go)
  - handshake 성공 후 `proxy.ClientProxy.StartLoop` 실행.

#### 3.3A Stream-based DTLS Tunneling / 스트림 기반 DTLS 터널링

현재 HTTP 터널링은 **단일 JSON Envelope + 단일 DTLS 쓰기** 방식(요청/응답 바디 전체를 한 번에 전송)이므로,
대용량 응답 바디에서 UDP MTU 한계로 인한 `sendto: message too long` 문제가 발생할 수 있습니다.
프로덕션 전 단계에서 이 한계를 제거하기 위해, DTLS 위 애플리케이션 프로토콜을 **완전히 스트림/프레임 기반**으로 재설계합니다.
The current tunneling model uses a **single JSON envelope + single DTLS write per HTTP message**, which can hit UDP MTU limits (`sendto: message too long`) for large bodies.
Before production, we will redesign the application protocol over DTLS to be fully **stream/frame-based**.

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

- [x] 수신 측 스트림 상태 관리 로직 설계
  - 스트림별로 다음 상태를 유지합니다.
    For each stream, maintain:
    - `expectedSeq` (다음에 연속으로 기대하는 Seq, 초기값 0)
      `expectedSeq` – next contiguous sequence expected (starts at 0)
    - `received` (map[uint64][]byte) – 도착했지만 아직 순서가 맞지 않은 chunk 버퍼
      `received` – buffer for out-of-order chunks
    - `lastAckSent`, `lostBuffer` – 마지막 ACK 상태 및 누락 시퀀스 기록
      `lastAckSent`, `lostBuffer` – last acknowledged seq and known missing sequences
  - `StreamData{ID, Seq, Data}` 수신 시:
    When receiving `StreamData{ID, Seq, Data}`:
    - `Seq == expectedSeq` 인 경우: 바로 상위(HTTP Body writer)에 전달 후,
      `expectedSeq++` 하면서 `received` map 에 쌓인 연속된 Seq 들을 순서대로 flush.
      If `Seq == expectedSeq`, deliver to the HTTP body writer, increment `expectedSeq`, and flush any contiguous buffered seqs.
    - `Seq > expectedSeq` 인 경우: `received[Seq] = Data` 로 버퍼링하고,
      `expectedSeq` ~ `Seq-1` 구간 중 비어 있는 Seq 들을 `lostBuffer` 에 추가.
      If `Seq > expectedSeq`, buffer as out-of-order and mark missing seqs in `lostBuffer`.

- [x] 수신 측 StreamAck 전송 정책
  - 주기적 타이머 또는 일정 수의 프레임 처리 후에 `StreamAck` 를 전송합니다.
    Send `StreamAck` periodically or after processing N frames:
    - `AckSeq = expectedSeq - 1` (연속 수신 완료 지점)
      `AckSeq = expectedSeq - 1` – last contiguous sequence received
    - `LostSeqs` 는 윈도우 내 손실 시퀀스 중 상한 개수까지만 포함 (과도한 길이 방지).
      `LostSeqs` should only include a bounded set of missing seqs within the receive window.

- [x] 송신 측 재전송 로직
  - 스트림별로 다음 상태를 유지합니다.
    For each stream on the sender:
    - `sendSeq` – 송신에 사용할 다음 Seq (0부터 시작)
    - `outstanding` – map[seq]*FrameState (`data`, `lastSentAt`, `retryCount` 포함)
  - 새 chunk 전송 시:
    On new chunk:
    - `seq := sendSeq`, `sendSeq++`, `outstanding[seq] = FrameState{...}`,
      `StreamData{ID, Seq: seq, Data}` 전송.
  - `StreamAck{AckSeq, LostSeqs}` 수신 시:
    On receiving `StreamAck`:
    - `seq <= AckSeq` 인 `outstanding` 항목은 **모두 삭제** (해당 지점까지 연속 수신으로 간주).
      Delete all `outstanding` entries with `seq <= AckSeq`.
    - `LostSeqs` 에 포함된 시퀀스는 즉시 재전송 (`retryCount++`, `lastSentAt = now` 업데이트).
      Retransmit frames whose seqs are listed in `LostSeqs`.
  - 타임아웃 기반 재전송:
    Timeout-based retransmission:
    - 주기적으로 `outstanding` 을 순회하며 `now - lastSentAt > RTO` 인 프레임을 재전송 (단순 고정 RTO 로 시작).
      Periodically scan `outstanding` and retransmit frames that exceed a fixed RTO.

---

##### 3.3A.3 HTTP ↔ 스트림 매핑 (서버/클라이언트)
##### 3.3A.3 HTTP ↔ stream mapping (server/client)

- [x] 서버 → 클라이언트 요청 스트림: [`cmd/server/main.go`](cmd/server/main.go:200)
  - 현재 `ForwardHTTP` 는 단일 `HTTPRequest`/`HTTPResponse` 를 처리하는 구조입니다.
    Currently `ForwardHTTP` handles a single `HTTPRequest`/`HTTPResponse` pair.
  - 스트림 모드에서는 다음과 같이 바꿉니다.
    In stream mode:
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

- [ ] JSON 기반 스트림 프로토콜의 1단계 구현/안정화 이후, 직렬화 포맷 재검토
  - 현재는 디버깅/호환성 관점에서 JSON `Envelope` + base64 `[]byte` encoding 이 유리합니다.
    For now, JSON `Envelope` + base64-encoded `[]byte` is convenient for debugging and compatibility.
  - HTTP 바디 chunk 가 MTU-safe 크기(예: 4KiB)로 제한되므로, JSON 오버헤드는 수용 가능합니다.
    Since body chunks are bounded to a safe MTU-sized payload, JSON overhead is acceptable initially.
- [ ] 필요 시 length-prefix 이진 프레임(Protobuf 등)으로 전환
  - 동일한 logical model (`StreamOpen` / `StreamData(seq)` / `StreamClose` / `StreamAck`)을 유지한 채,
    wire-format 만 Protobuf 또는 MsgPack 등의 length-prefix binary 프레이밍으로 교체할 수 있습니다.
    We can later keep the same logical model and swap the wire format for Protobuf or other length-prefix binary framing.
- [x] 이 전환은 `internal/protocol` 내 직렬화 레이어를 얇은 abstraction 으로 감싸 구현할 수 있습니다.
  - 현재는 [`internal/protocol/codec.go`](internal/protocol/codec.go:1) 에 `WireCodec` 인터페이스와 JSON 기반 `DefaultCodec` 을 도입하여,
    추후 Protobuf/이진 포맷으로 교체할 때 호출자는 `protocol.DefaultCodec` 만 사용하도록 분리해 두었습니다.
  - This has been prepared via [`internal/protocol/codec.go`](internal/protocol/codec.go:1), which introduces a `WireCodec` interface
    and a JSON-based `DefaultCodec` so that future Protobuf/binary codecs can be swapped in behind the same API.

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

- [ ] Prometheus 메트릭 노출 및 서버 wiring
  - `cmd/server/main.go` 에 Prometheus `/metrics` 엔드포인트 추가 (예: promhttp.Handler).
  - DTLS 세션 수, DTLS 핸드셰이크 성공/실패 수, HTTP/Proxy 요청 수 및 에러 수에 대한 카운터/게이지 메트릭 정의.
  - 도메인, 클라이언트 ID, request_id 등의 라벨 설계 및 현재 구조적 로깅 필드와 일관성 유지.

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

- [ ] 서버 Proxy 코어 구현 및 HTTPS ↔ DTLS 라우팅.  
- [ ] 클라이언트 Proxy 루프 구현 및 로컬 서비스 연동.  
- [ ] End-to-end HTTP 요청/응답 터널링 E2E 테스트.  

### Milestone 3 — ACME + TLS/DTLS 정식 인증

- [x] ACME 매니저 구현 (lego 기반).
- [x] HTTPS/DTLS 리스너에 ACME 인증서 주입.
- [ ] ACME 고급 기능 및 운영 전략 정리 (예: TLS-ALPN-01, 인증서 롤오버/장애 대응 전략).

### Milestone 4 — Observability & Hardening

- [ ] Prometheus/Loki/Grafana 통합.  
- [ ] 에러/리트라이/타임아웃 정책 정교화.  
- [ ] 보안/구성 최종 점검 및 문서화.  

---

이 `progress.md` 파일은 아키텍처/코드 변경에 따라 수시로 업데이트하며, Milestone 기준으로 완료 여부를 체크해 나가면 된다.  
This `progress.md` file should be updated as the architecture and code evolve, using the milestones above as a checklist.