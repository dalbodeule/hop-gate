# HopGate API Reference / HopGate API 명세

This document describes the externally visible APIs currently implemented in HopGate, with English as the primary language and Korean descriptions in parallel.  
이 문서는 현재 HopGate에 구현된 외부 공개 API를 정리한 것으로, 영어를 기본으로 하며 한국어 설명을 병기합니다.

---

## 1. Admin Plane HTTP API / 관리 Plane HTTP API

The admin plane is exposed under the HTTPS endpoint of the HopGate server.  
관리 Plane은 HopGate 서버의 HTTPS 엔드포인트 아래에서 동작합니다.

- Base URL: `https://{HOP_SERVER_DOMAIN}/api/v1/admin`  
  기본 URL: `https://{HOP_SERVER_DOMAIN}/api/v1/admin`
- Implementation: [`internal/admin/http.go`](internal/admin/http.go)  
  구현 위치: [`internal/admin/http.go`](internal/admin/http.go)
- Wired into server main: [`cmd/server/main.go`](cmd/server/main.go)  
  서버 메인에서의 연결: [`cmd/server/main.go`](cmd/server/main.go)

### 1.1 Authentication / 인증

- Header: `Authorization: Bearer {HOP_ADMIN_API_KEY}`  
  헤더: `Authorization: Bearer {HOP_ADMIN_API_KEY}`
- Env var: `HOP_ADMIN_API_KEY`  
  환경 변수: `HOP_ADMIN_API_KEY`
- If the key is missing or incorrect, the API responds with `401 Unauthorized`.  
  키가 없거나 값이 올바르지 않으면 `401 Unauthorized` 로 응답합니다.

### 1.2 Domain Register API / 도메인 등록 API

- Method: `POST`  
  메서드: `POST`
- Path: `/api/v1/admin/domains/register`  
  경로: `/api/v1/admin/domains/register`
- Purpose: Register a new domain and issue a 64-character client API key bound to that domain.  
  목적: 새로운 도메인을 등록하고 해당 도메인에 매핑된 64자 클라이언트 API 키를 발급합니다.

#### 1.2.1 Request / 요청

- Content-Type: `application/json`
- Body:

```json
{
  "domain": "app.example.com",
  "memo": "my staging app"
}
```

- Fields  
  필드

- `domain` (string, required)  
  - FQDN, must contain at least one dot, case-insensitive.  
  - 공백이 없어야 하며, 최소 한 개 이상의 점(`.`)을 포함하는 FQDN이어야 합니다.
- `memo` (string, optional)  
  - Free-form memo for administrators; may be empty.  
  - 관리자를 위한 자유 형식 메모로, 비어 있어도 됩니다.

#### 1.2.2 Successful Response / 성공 응답

- Status: `200 OK`
- Body:

```json
{
  "success": true,
  "client_api_key": "abcd1234...wxyz5678"
}
```

- Fields  
  필드

- `success` (boolean) — always `true` on success.  
  `success` (boolean) — 성공 시 항상 `true` 입니다.
- `client_api_key` (string, length 64) — client API key bound to the registered domain.  
  `client_api_key` (string, 길이 64) — 등록된 도메인에 매핑된 클라이언트 API 키입니다.

#### 1.2.3 Error Responses / 에러 응답

- `400 Bad Request`
  - Invalid JSON body or missing/empty `domain`.  
  - JSON 바디가 잘못되었거나 `domain` 이 비어 있는 경우.
  - Body:

```json
{
  "success": false,
  "error": "invalid request body"
}
```

  or

```json
{
  "success": false,
  "error": "domain is required"
}
```

- `401 Unauthorized`
  - Missing or invalid `Authorization` header.  
  - `Authorization` 헤더가 없거나 잘못된 경우.
  - Body:

```json
{
  "success": false,
  "error": "unauthorized"
}
```

- `500 Internal Server Error`
  - Database or internal logic error while registering domain.  
  - 도메인 등록 처리 중 데이터베이스 또는 내부 로직 에러가 발생한 경우.
  - Body:

```json
{
  "success": false,
  "error": "internal error"
}
```

### 1.3 Domain Unregister API / 도메인 해제 API

- Method: `POST`  
  메서드: `POST`
- Path: `/api/v1/admin/domains/unregister`  
  경로: `/api/v1/admin/domains/unregister`
- Purpose: Unregister a domain using the `(domain, client_api_key)` pair.  
  목적: `(domain, client_api_key)` 조합을 사용해 도메인 등록을 해제합니다.

#### 1.3.1 Request / 요청

- Content-Type: `application/json`
- Body:

```json
{
  "domain": "app.example.com",
  "client_api_key": "abcd1234...wxyz5678"
}
```

- Fields  
  필드

- `domain` (string, required)  
  - Same normalization rule as the register API (lowercased, trimmed, FQDN-like).  
  - 등록 API와 동일한 정규화 규칙(소문자, 공백 제거, FQDN 형태)을 따릅니다.
- `client_api_key` (string, required)  
  - Exact client API key previously issued for the domain.  
  - 해당 도메인에 대해 이전에 발급된 클라이언트 API 키와 정확히 일치해야 합니다.

#### 1.3.2 Successful Response / 성공 응답

- Status: `200 OK`
- Body:

```json
{
  "success": true
}
```

- `success` (boolean) — `true` if the domain was found and deleted.  
  `success` (boolean) — 해당 도메인이 존재했고 삭제되었을 때 `true` 입니다.

#### 1.3.3 Error Responses / 에러 응답

- `400 Bad Request`
  - Invalid JSON body, or `domain` or `client_api_key` is missing/empty.  
  - JSON 바디가 잘못되었거나 `domain` 혹은 `client_api_key` 가 비어 있는 경우.
  - Body:

```json
{
  "success": false,
  "error": "invalid request body"
}
```

  or

```json
{
  "success": false,
  "error": "domain and client_api_key are required"
}
```

- `401 Unauthorized`
  - Missing or invalid `Authorization` header.  
  - `Authorization` 헤더가 없거나 잘못된 경우.
  - Same JSON structure as in the register API.  
  - JSON 응답 구조는 등록 API와 동일합니다.

- `500 Internal Server Error`
  - Internal error while unregistering or deleting the domain.  
  - 도메인 해제/삭제 처리 중 내부 에러가 발생한 경우.
  - Body:

```json
{
  "success": false,
  "error": "internal error"
}
```

---

## 2. Public HTTPS Reverse Proxy Entry / 공개 HTTPS 프록시 엔트리

HopGate acts as an HTTPS reverse proxy, forwarding incoming HTTP(S) requests for registered domains over DTLS to connected clients.  
HopGate는 등록된 도메인에 대한 HTTP(S) 요청을 DTLS를 통해 클라이언트로 전달하는 HTTPS 리버스 프록시 역할을 합니다.

- Entry points:  
  진입점:
  - `http://{HOP_SERVER_DOMAIN}/...`  
  - `https://{HOP_SERVER_DOMAIN}/...`
- Implementation: [`cmd/server/main.go`](cmd/server/main.go)  
  구현 위치: [`cmd/server/main.go`](cmd/server/main.go)

Behavior summary:  
동작 요약:

- If the path starts with `/.well-known/acme-challenge/`, HopGate serves static ACME HTTP-01 challenge files from `HOP_ACME_WEBROOT`.  
  경로가 `/.well-known/acme-challenge/` 로 시작하면 HopGate는 `HOP_ACME_WEBROOT` 디렉터리에서 ACME HTTP-01 챌린지 파일을 정적으로 서빙합니다.
- For other paths, HopGate looks up an active DTLS session for the incoming `Host` and forwards the HTTP request over that session.  
  그 외 경로에 대해서는 들어온 `Host` 에 해당하는 활성 DTLS 세션을 찾은 뒤, HTTP 요청을 해당 세션을 통해 포워딩합니다.
- If no DTLS session is available for the host, the server responds with `502 Bad Gateway`.  
  해당 호스트에 대한 DTLS 세션이 없으면 서버는 `502 Bad Gateway` 로 응답합니다.

The reverse-proxy behavior is not a separate REST API but the core behavior of the HopGate server.  
이 프록시 동작은 별도의 REST API라기보다는 HopGate 서버의 핵심 동작입니다.

---

## 3. DTLS Handshake Protocol / DTLS 핸드셰이크 프로토콜

The DTLS handshake between server and client uses a small JSON-based protocol to authenticate the `(domain, client_api_key)` pair before establishing the HTTP tunneling session.  
서버와 클라이언트 사이의 DTLS 핸드셰이크는 HTTP 터널링 세션을 열기 전 `(domain, client_api_key)` 조합을 인증하기 위해 간단한 JSON 기반 프로토콜을 사용합니다.

- Implementation: [`internal/dtls/handshake.go`](internal/dtls/handshake.go)  
  구현 위치: [`internal/dtls/handshake.go`](internal/dtls/handshake.go)

### 3.1 Handshake Request / 핸드셰이크 요청

The client sends a JSON message over the DTLS session:  
클라이언트는 DTLS 세션 위로 다음과 같은 JSON 메시지를 전송합니다.

```json
{
  "domain": "app.example.com",
  "client_api_key": "abcd1234...wxyz5678"
}
```

- `domain` and `client_api_key` must match a registered domain entry for the handshake to succeed.  
  핸드셰이크가 성공하려면 `domain` 과 `client_api_key` 가 등록된 도메인 정보와 일치해야 합니다.

### 3.2 Handshake Response / 핸드셰이크 응답

The server responds with:  
서버는 다음과 같은 구조로 응답합니다.

```json
{
  "ok": true,
  "message": "handshake ok",
  "domain": "app.example.com"
}
```

- On failure, `ok` is `false` and `message` contains a human-readable reason (e.g., `"invalid domain or api key"`).  
  실패 시 `ok` 는 `false` 이며, `message` 에 `"invalid domain or api key"` 와 같은 사람이 읽을 수 있는 이유가 담깁니다.

A successful handshake registers the DTLS session for the given domain so that subsequent HTTPS requests for that domain can be tunneled through the session.  
핸드셰이크가 성공하면 해당 도메인에 대해 DTLS 세션이 등록되어, 이후 그 도메인으로 들어오는 HTTPS 요청이 이 세션을 통해 터널링될 수 있습니다.

---

## 4. Additional Admin Plane APIs / 추가 관리 Plane API

This section describes two helper admin APIs for checking whether a domain is registered and retrieving its detailed status.  
이 섹션은 도메인 등록 여부를 확인하고 상세 상태를 조회하기 위한 두 가지 관리용 API를 설명합니다.

Implementation references / 구현 위치:

- Admin HTTP handlers: [`internal/admin/http.go`](internal/admin/http.go:197)  
- Domain service methods: [`internal/admin/service.go`](internal/admin/service.go:129)

### 4.1 Check Domain Registration (exists) / 도메인 등록 여부 확인

- Method / 메서드: `GET`
- Path / 경로: `/api/v1/admin/domains/exists`
- Authentication / 인증:
  - Same as other admin APIs: `Authorization: Bearer {HOP_ADMIN_API_KEY}`  
    다른 Admin API와 동일하게 `Authorization: Bearer {HOP_ADMIN_API_KEY}` 헤더 사용.
- Purpose / 목적:
  - Check if a given domain is already registered in the `Domain` table.  
    특정 도메인이 `Domain` 테이블에 이미 등록되어 있는지 확인합니다.

#### 4.1.1 Request / 요청

- Query Parameters / 쿼리 파라미터:
  - `domain` (string, required) — domain to check.  
    `domain` (string, 필수) — 확인할 도메인.

- Example / 예시:

```http
GET /api/v1/admin/domains/exists?domain=app.example.com HTTP/1.1
Host: {HOP_SERVER_DOMAIN}
Authorization: Bearer {HOP_ADMIN_API_KEY}
```

#### 4.1.2 Successful Response / 성공 응답

- Status: `200 OK`
- Body:

```json
{
  "success": true,
  "exists": true
}
```

- Fields / 필드:
  - `success` (bool) — request processed successfully.  
    요청이 정상 처리되었는지 여부.
  - `exists` (bool) — whether the domain is currently registered.  
    도메인이 현재 등록되어 있는지 여부.

If the domain is not registered:  
도메인이 등록되어 있지 않으면:

```json
{
  "success": true,
  "exists": false
}
```

#### 4.1.3 Error Responses / 에러 응답

- `400 Bad Request`
  - Missing or empty `domain` query parameter.  
    `domain` 쿼리 파라미터가 없거나 비어 있는 경우.

```json
{
  "success": false,
  "error": "domain is required"
}
```

- `401 Unauthorized`
  - Missing or invalid `Authorization` header.  
    `Authorization` 헤더가 없거나 잘못된 경우.

```json
{
  "success": false,
  "error": "unauthorized"
}
```

- `500 Internal Server Error`
  - Internal error while checking domain existence (e.g., DB error).  
    도메인 존재 여부 확인 중 내부(DB 등) 에러가 발생한 경우.

```json
{
  "success": false,
  "error": "internal error"
}
```

---

### 4.2 Domain Status API / 도메인 상태 조회 API

- Method / 메서드: `GET`
- Path / 경로: `/api/v1/admin/domains/status`
- Authentication / 인증:
  - `Authorization: Bearer {HOP_ADMIN_API_KEY}`
- Purpose / 목적:
  - Retrieve detailed information about a domain if registered, including memo and timestamps.  
    도메인이 등록되어 있다면 메모, 생성/수정 시각 등 상세 정보를 조회합니다.

#### 4.2.1 Request / 요청

- Query Parameters / 쿼리 파라미터:
  - `domain` (string, required) — domain to inspect.  
    `domain` (string, 필수) — 조회할 도메인.

- Example / 예시:

```http
GET /api/v1/admin/domains/status?domain=app.example.com HTTP/1.1
Host: {HOP_SERVER_DOMAIN}
Authorization: Bearer {HOP_ADMIN_API_KEY}
```

#### 4.2.2 Successful Response (exists) / 성공 응답 (도메인 존재 시)

- Status: `200 OK`
- Body:

```json
{
  "success": true,
  "exists": true,
  "domain": "app.example.com",
  "memo": "my staging app",
  "created_at": "2025-01-01T12:34:56Z",
  "updated_at": "2025-01-02T08:00:00Z"
}
```

- Fields / 필드:
  - `success` (bool) — request processed successfully.  
    요청이 정상 처리되었는지 여부.
  - `exists` (bool) — **true** if the domain record exists.  
    도메인 레코드가 존재하면 `true`.
  - `domain` (string) — normalized domain name.  
    정규화된 도메인 이름.
  - `memo` (string) — administrator memo.  
    관리자 메모.
  - `created_at` (string, RFC3339) — creation timestamp.  
    생성 시각(RFC3339 문자열).
  - `updated_at` (string, RFC3339) — last update timestamp.  
    마지막 수정 시각(RFC3339 문자열).

#### 4.2.3 Successful Response (not exists) / 성공 응답 (도메인 미존재 시)

If the domain is not found in the database:  
해당 도메인이 DB에 존재하지 않으면:

```json
{
  "success": true,
  "exists": false
}
```

- No error; this is a normal “not registered” state.  
  에러가 아니며, “등록되지 않음” 상태를 의미합니다.

#### 4.2.4 Error Responses / 에러 응답

- `400 Bad Request`
  - Missing or empty `domain` query parameter.  

```json
{
  "success": false,
  "error": "domain is required"
}
```

- `401 Unauthorized`
  - Missing or invalid `Authorization` header.  

```json
{
  "success": false,
  "error": "unauthorized"
}
```

- `500 Internal Server Error`
  - Internal error while fetching domain status.  

```json
{
  "success": false,
  "error": "internal error"
}
```
