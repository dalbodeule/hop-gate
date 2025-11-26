# Commit Message Convention / 커밋 메시지 규칙

이 문서는 git-rewrite-commits(node 기반 도구)가 참고하는 **커밋 메시지 형식 규칙**을 정의합니다.  
This document defines the **commit message format** used by the node-based tool git-rewrite-commits.

---

## 1. 기본 형식 (Basic Format)

### 1.1 형식 (Format)

- **형식 / Format**  
  ```text
  [type] short description [BREAK]
  ```
- 규칙 / Rules:
  - `type` 은 반드시 대괄호 `[]` 안에 들어가야 합니다.  
    `type` MUST be enclosed in square brackets `[]`.
  - `short description` 에는 작업 내용을 **간단하고 명확하게** 한 줄로 작성합니다.  
    `short description` MUST briefly and clearly describe what the commit does.
  - **중대한 변경(BREAKING CHANGE)** 가 있을 경우, 메시지 끝에 `[BREAK]` 를 추가합니다.  
    If there is a **breaking change**, append `[BREAK]` at the end.

### 1.2 예시 (Examples)

- 일반 커밋 / Normal commits
  - `[feat] add dtls handshake client`  
  - `[fix] wrong dtls listen port`  
  - `[docs] update README ko/en`

- 브레이킹 체인지 / Breaking changes
  - `[config] rename env variables for server port [BREAK]`  
  - `[feat] change dtls handshake message format [BREAK]`  
  - `[refactor] remove legacy proxy api [BREAK]`

---

## 2. 타입 규칙 (Type Rules)

아래 타입들은 **우선순위가 높은 것부터** 나열되어 있습니다.  
Commit types are listed in **priority order** (highest first).

### 2.1 High-priority impact types (상위 우선순위 타입)

1. `[breakfix]` – **긴급/심각한 문제 수정 (긴급 영향)**  
   - 사용 시점 / When to use:
     - 프로덕션 장애나 보안 취약점 등, 즉시 수정이 필요한 심각한 문제를 해결할 때.  
       For critical production issues or security fixes requiring immediate attention.
   - 예 / Examples:
     - `[breakfix] fix dtls denial-of-service bug [BREAK]`
     - `[breakfix] hotfix wrong admin auth check`

2. `[feat]` – **새 기능 추가 (Feature)**  
   - 새로운 기능, API, 큰 동작 변화 추가.  
     New features, APIs, or significant behavioral changes.
   - 예 / Examples:
     - `[feat] add admin domain register api`
     - `[feat] support multiple dtls clients per domain [BREAK]`

3. `[config]` – **설정/환경/배포 관련 변경 (Config / Env / Infra)**  
   - 환경 변수, 설정 파일, 인프라 관련 변경.  
     Configuration, environment variables, infra-related changes.
   - **환경변수 이름/의미가 바뀌면 반드시 `[BREAK]` 추가**.  
     If env names/semantics change, ALWAYS append `[BREAK]`.
   - 예 / Examples:
     - `[config] add HOP_SERVER_DEBUG env`
     - `[config] rename HOP_CLIENT_SERVER_ADDR to HOP_CLIENT_DTLS_ADDR [BREAK]`

4. `[db]` – **데이터베이스/스키마 변경 (Database / Schema)**  
   - ent 스키마 변경, 마이그레이션, 인덱스 변경 등.  
     ent schema changes, migrations, indexes, etc.
   - 호환성이 깨지는 스키마 변경이면 `[BREAK]`.  
     Use `[BREAK]` for incompatible schema changes.
   - 예 / Examples:
     - `[db] add domain uuid primary key`
     - `[db] drop legacy domain table [BREAK]`

5. `[refactor]` – **리팩터링 (Refactor)**  
   - 기능 변경 없이 구조/설계 개선.  
     Structural/design improvements without changing behavior.
   - 예 / Examples:
     - `[refactor] extract dtls handshake into internal/dtls`
     - `[refactor] simplify admin handler routing`

---

### 2.2 Normal change types (일반 변경 타입)

6. `[fix]` – **버그 수정 (Bug Fix, non-critical)**  
   - 치명적이지 않은 일반 버그 수정.  
     Non-critical bug fixes.
   - 예 / Examples:
     - `[fix] handle empty domain in admin register`
     - `[fix] correct log field name for client_id`

7. `[perf]` – **성능 개선 (Performance)**  
   - 성능 최적화, 메모리/지연 시간 감소.  
     Performance improvements (latency, memory, throughput).
   - 예 / Examples:
     - `[perf] reuse dtls buffers`
     - `[perf] reduce log allocations`

8. `[docs]` – **문서 (Documentation)**  
   - README, ARCHITECTURE, 주석 등 문서 변경.  
     Documentation changes (README, ARCHITECTURE, comments).
   - 예 / Examples:
     - `[docs] add ko/en README`
     - `[docs] update architecture handshake flow`

9. `[test]` – **테스트 (Tests)**  
   - 유닛/통합 테스트 추가/수정.  
     Adding or updating tests.
   - 예 / Examples:
     - `[test] add dtls handshake unit tests`
     - `[test] fix flaky proxy integration test`

10. `[build]` – **빌드/도구 (Build / Tooling)**  
    - Makefile, Dockerfile, CI 스크립트 등 빌드 파이프라인 관련.  
      Build pipeline changes (Makefile, Dockerfile, CI).
    - 예 / Examples:
      - `[build] add dockerfile for server`
      - `[build] update make targets for client`

11. `[chore]` – **관리용 잡일 (Chore / Maintenance)**  
    - 코드 포맷팅, 의존성 업그레이드, 단순 정리 등.  
      Maintenance tasks: formatting, dependency bumps, trivial cleanups.
    - 예 / Examples:
      - `[chore] bump pion dtls to v3.x`
      - `[chore] clean up unused imports`

---

### 2.3 Optional / Special types (선택적 / 특수 타입)

12. `[debug]` – **디버깅 / 로깅 임시 커밋 (Temporary Debug)**  
    - 로그 추가, 임시 디버그 코드, 포트/주소를 바꿔가며 실험하는 커밋.  
      Temporary debug logs or experimental changes.
    - 브레이킹 변경(예: 포트/환경변수 변경)이 포함되면 `[BREAK]` 추가.  
      Append `[BREAK]` if it includes breaking changes (e.g., port/env change).
    - 예 / Examples:
      - `[debug] log dtls handshake flow`
      - `[debug] change client port for local test [BREAK]`

13. `[revert]` – **이전 커밋 되돌리기 (Revert)**  
    - 이전 커밋을 되돌리는 경우.  
      Reverts a previous commit.
    - 예 / Examples:
      - `[revert] revert dtls handshake change`

14. `[wip]` – **작업 진행 중 (Work in Progress)**  
    - 미완료 상태의 임시 커밋 (가능하면 main/master에는 남기지 않기).  
      Work-in-progress commits (avoid keeping them on main/master).
    - 예 / Examples:
      - `[wip] refactor proxy routing table`

---

## 3. 브레이킹 변경 표시 (Marking Breaking Changes)

**중대한 변경사항(브레이킹 체인지)이 있을 때는 항상 메시지 끝에 `[BREAK]` 를 붙입니다.**  
Whenever there is a **breaking change**, always append `[BREAK]` at the end of the message.

브레이킹 변경의 예 / Examples of breaking changes:

- 환경 변수 이름/의미 변경 (Env var name/semantics change)
  - 예: `HOP_SERVER_DTLS_LISTEN` → `HOP_SERVER_DTLS_ADDR`  
  - Example: `HOP_SERVER_DTLS_LISTEN` → `HOP_SERVER_DTLS_ADDR`  
  - 커밋 예시 / Commit example:  
    - `[config] rename dtls listen env to HOP_SERVER_DTLS_ADDR [BREAK]`

- DB 스키마 비호환 변경 (Incompatible DB schema change)
  - 컬럼 삭제, 타입 변경, 테이블 드롭 등.  
    Dropping columns, changing types, dropping tables, etc.
  - 예 / Example:  
    - `[db] drop legacy domain table [BREAK]`

- 외부 API / 프로토콜 계약 변경 (External API / protocol contract changes)
  - 핸드셰이크 메시지 포맷 변경, HTTP 경로/쿼리 변화 등.  
    Changing handshake message format, HTTP paths, query params, etc.
  - 예 / Example:  
    - `[feat] change dtls handshake json fields [BREAK]`

- 포트/리스너 동작 변경 (Port / listener behavior change)
  - 기본 포트 변경, TLS/DTLS 포트 매핑 변경 등.  
    Changing default ports, TLS/DTLS mapping, etc.
  - 예 / Example:  
    - `[config] change default dtls port to 8443 [BREAK]`

---

## 4. 요약 (Summary)

- 커밋 메시지는 항상 다음 형식을 사용합니다:  
  Always use this format for commit messages:
  ```text
  [type] short description [BREAK]
  ```
- `type` 은 위에서 정의한 타입 중 하나를 사용합니다.  
  `type` MUST be one of the defined types above.
- **환경 변수, 스키마, 프로토콜 등 호환성을 깨는 변경이 있다면 `[...] [BREAK]` 를 반드시 추가합니다.**  
  If there are any compatibility-breaking changes (env, schema, protocol, etc.), ALWAYS append `[BREAK]`.

이 규칙을 따르면, git-rewrite-commits 및 기타 도구들이 커밋 히스토리를 안정적으로 분석하고 재작성할 수 있습니다.  
Following these rules allows git-rewrite-commits and other tools to reliably analyze and rewrite commit history.
