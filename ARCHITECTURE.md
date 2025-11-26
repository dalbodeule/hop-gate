# hop-gate 아키텍처 개요

이 프로젝트는 인터넷에서 들어오는 HTTP(S) 트래픽을 여러 클라이언트로 터널링해 주는 게이트웨이(서버)와, 서버의 지시에 따라 로컬 네트워크에 HTTP 요청을 수행하는 클라이언트로 구성된다.

## 전체 구조

- 단일 Go 모듈: `hop-gate`
- 실행 바이너리 2개:
  - 서버: 공인 포트 80/443 점유, ACME로 인증서 자동 발급/갱신, HTTP Reverse Proxy 및 DTLS 터널 엔드포인트
  - 클라이언트: DTLS를 통해 서버에 접속, 서버가 전달한 HTTP 요청을 로컬에서 실행 후 응답을 서버로 전달

## 디렉터리 레이아웃

```text
.
├── cmd/
│   ├── server/              # 서버 바이너리 엔트리 포인트
│   └── client/              # 클라이언트 바이너리 엔트리 포인트
├── internal/
│   ├── config/              # 서버/클라이언트 공통 설정 로딩
│   ├── acme/                # ACME(예: Let's Encrypt) 인증서 발급/갱신 로직
│   ├── dtls/                # DTLS 세션 관리 및 암호화 채널 추상화
│   ├── proxy/               # HTTP Proxy / 터널링 코어 로직
│   ├── protocol/            # 서버-클라이언트 메시지 프로토콜 정의
│   └── logging/             # 공통 로깅 유틸
└── pkg/
    └── util/                # 재사용 가능한 유틸리티 (선택 사항)
```

### cmd/

- [`cmd/server/main.go`](cmd/server/main.go)
  - 서버 설정 로딩 (리스닝 주소, ACME 도메인, Proxy 라우팅 설정 등)
  - ACME 매니저 초기화 및 인증서 자동 관리
  - HTTP(80) → ACME HTTP-01 챌린지 및 80 리다이렉트 처리
  - HTTPS(443/TCP) → 외부 클라이언트의 HTTP(S) 요청 수신
  - 443/UDP(또는 별도 포트) → DTLS 서버 소켓 생성
  - DTLS 세션과 HTTP Proxy 코어를 연결

- [`cmd/client/main.go`](cmd/client/main.go)
  - 클라이언트 설정 로딩 (접속할 서버 주소, 인증 정보, 로컬 HTTP 타깃 포트 매핑 등)
  - DTLS 클라이언트 세션 생성 및 재접속 로직
  - 서버에서 내려오는 HTTP 요청 메시지를 받아 로컬 HTTP 서버/서비스로 프록시
  - HTTP 응답을 서버로 전송

### internal/config

서버와 클라이언트가 공통으로 사용하는 설정 스키마를 정의한다.

- 서버 설정 예시
  - 리스닝 주소: `http_listen`, `https_listen`, `dtls_listen`
  - ACME 설정: `acme_email`, `acme_ca`, `acme_cache_dir`
  - 도메인/서브도메인: 메인 도메인, 프록시 서브도메인 목록
  - 라우팅 규칙: 도메인/패스 → 클라이언트 ID 매핑
- 클라이언트 설정 예시
  - 서버 주소 및 포트 (DTLS)
  - 클라이언트 식별자 및 인증 토큰/키
  - 로컬 HTTP 타깃 매핑: `service_name` → `127.0.0.1:PORT`

### internal/acme

- ACME 클라이언트 래퍼
- 메인 도메인 및 Proxy 서브도메인(또는 별도 정의 도메인)용 인증서 발급
- HTTP-01 또는 TLS-ALPN-01 챌린지를 위한 훅 제공
- 자동 갱신 및 인증서 캐시(파일 또는 디렉터리) 관리

서버 바이너리에서는 이 패키지에서 제공하는 인증서 매니저를 이용해 HTTPS(443)와 DTLS(443/UDP)의 인증서를 동일하게 또는 별도로 주입할 수 있다.

### internal/dtls

- DTLS 라이브러리(pion/dtls 등)에 대한 얇은 추상화 레이어
- 서버:
  - 다중 클라이언트 세션 관리 (클라이언트 ID 매핑)
  - 재접속 및 세션 타임아웃 처리
- 클라이언트:
  - 서버와의 DTLS 핸드셰이크 및 재연결 로직
  - 서버 인증(ACME로 발급된 인증서 체인 검증)

이 레이어는 단순히 `io.ReadWriteCloser` 또는 스트림 추상화를 제공해 상위 `proxy`/`protocol` 레이어에서 재사용 가능하게 한다.

### internal/protocol

서버와 클라이언트가 DTLS 위에서 교환하는 메시지 포맷과 흐름을 정의한다.

- 요청/응답 단위의 메시지 구조:
  - `request_id`: 요청 식별자
  - HTTP 메서드, URL, 헤더, 바디
  - 타깃 서비스/포트 식별자
- 응답 메시지 구조:
  - `request_id`
  - HTTP 상태 코드, 헤더, 바디
- 인코딩 방식: JSON, MsgPack 또는 Protobuf 등 (초기에는 JSON으로 시작해도 됨)
- Flow 제어 및 에러 코드 정의

### internal/proxy

#### 서버 측 역할

- 공인 HTTPS 엔드포인트에서 들어오는 HTTP 요청 수신
- 도메인/패스 → 클라이언트 ID/서비스 매핑 룰에 따라 대상 클라이언트 선택
- `protocol` 패키지를 사용해 HTTP 요청을 메시지로 직렬화 후 DTLS 세션으로 전송
- 클라이언트로부터 받은 응답 메시지를 HTTP 응답으로 복원해 외부 클라이언트에 반환
- 타임아웃, 재시도, 클라이언트 장애 시 fallback 정책 등 처리

#### 클라이언트 측 역할

- DTLS 채널을 통해 서버가 내려보낸 HTTP 요청 메시지 수신
- 로컬에서 `net/http` 클라이언트 또는 직접 TCP 접속으로 지정된 `127.0.0.1:PORT`에 요청 수행
- 응답을 수신해 `protocol` 포맷으로 직렬화 후 서버로 전송
- 서버로부터 전달된 취소/타임아웃 신호에 따라 로컬 요청 중단

### internal/logging

- 구조적 로깅 래퍼 (예: zap, zerolog 등)
- 공통 로그 포맷 및 필드 (request_id, client_id, route 등) 정의

### pkg/util (선택)

- 재사용 가능한 헬퍼 유틸리티(에러 래핑, context 유틸 등)를 배치할 수 있는 공간이다.

## 요청 흐름 요약

1. 외부 사용자가 `https://proxy.example.com/service-a/path` 로 요청을 보낸다.
2. 서버의 HTTPS 리스너가 요청을 수신한다.
3. `proxy` 레이어가 라우팅 규칙에 따라 이 요청을 처리할 클라이언트(예: `client-1`)와 로컬 서비스(`service-a`)를 결정한다.
4. 요청을 `protocol` 포맷으로 직렬화해 `dtls` 레이어를 통해 `client-1`로 전송한다.
5. 클라이언트의 `proxy` 레이어가 메시지를 받아 로컬 `127.0.0.1:8080` 등으로 HTTP 요청을 수행한다.
6. 클라이언트는 응답을 수신해 `protocol` 포맷으로 직렬화 후 DTLS로 서버에 전송한다.
7. 서버는 응답 메시지를 HTTP 응답으로 복원해 원래의 외부 요청에 대한 응답으로 반환한다.

## 다음 단계

- 위 레이아웃대로 디렉터리와 최소한의 엔트리 포인트 파일을 생성한 뒤,
- `internal/config`에 설정 구조체와 YAML/JSON 로더를 정의하고,
- `internal/acme`에서 certmagic 또는 lego를 사용한 ACME 매니저를 구현하고,
- `internal/dtls`에서 pion/dtls 기반의 세션 래퍼를 만든 다음,
- `internal/protocol`과 `internal/proxy`를 순차적으로 구현하면 된다.