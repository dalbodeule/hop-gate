# HopGate: Project Introduction, Architecture & Roadmap / HopGate: 프로젝트 소개, 아키텍처, 로드맵

<!--
This document is intended to be posted as GitHub Discussions #1 (Announcement).
Copy & paste it into a new Discussion under the "Announcements" category and edit as needed.

이 문서는 GitHub Discussions의 #1 공지(Announcement)로 게시하기 위한 초안입니다.
"Announcements" 카테고리의 새 Discussion에 복사해 붙여 넣은 뒤 필요에 맞게 수정해서 사용하세요.
-->

## 1. What is HopGate? / HopGate란?

HopGate is a gateway that provides a **DTLS-based HTTP(S) tunnel** between a public server and multiple clients in private networks.
HopGate는 공인 서버와 여러 프라이빗 네트워크 클라이언트 사이에 **DTLS 기반 HTTP(S) 터널**을 제공하는 게이트웨이입니다.

Key characteristics / 주요 특징:

- The server listens on ports **80/443** and automatically issues/renews TLS certificates via **ACME** (e.g. Let's Encrypt).
- 서버는 **80/443 포트**를 점유하고 **ACME**(예: Let's Encrypt)를 통해 TLS 인증서를 자동 발급/갱신합니다.
- Transport between server and clients uses **DTLS**, tunneling HTTP request/response messages.
- 서버–클라이언트 간 전송은 **DTLS** 위에서 이루어지며 HTTP 요청/응답을 메시지로 터널링합니다.
- An **admin management plane (REST API)** handles domain registration/unregistration and client API key issuance.
- **관리 Plane(REST API)** 를 통해 도메인 등록/해제와 클라이언트 API Key 발급을 수행합니다.
- Logs are JSON-structured and designed to work well with **Prometheus + Loki + Grafana**.
- 로그는 JSON 구조로 출력되며 **Prometheus + Loki + Grafana** 스택과 잘 연동되도록 설계되었습니다.

For more details, see the architecture document in the repository. / 더 자세한 내용은 저장소의 아키텍처 문서를 참고해주세요.

- [`ARCHITECTURE.md`](../ARCHITECTURE.md)
- [`README.md`](../README.md)

## 2. Project goals & non-goals / 프로젝트 목표와 비목표

### Goals / 목표

- Provide a simple, self-hostable DTLS-based HTTP(S) tunneling gateway.
- 단순하고 셀프 호스트 가능한 DTLS 기반 HTTP(S) 터널링 게이트웨이를 제공합니다.
- Make it easy to expose services running in private networks securely to the public Internet.
- 프라이빗 네트워크 내부의 서비스를 안전하게 퍼블릭 인터넷에 노출할 수 있도록 돕습니다.
- Offer clear observability hooks (metrics, logs) for production operations.
- 프로덕션 운영을 위한 메트릭·로그 등 가시성(Observability)을 명확히 제공합니다.

### Non-goals (for now) / 현재 범위 밖(Non-goals)

- Being a full replacement for all kinds of VPN solutions.
- 모든 종류의 VPN 솔루션을 완전히 대체하는 것을 목표로 하지 않습니다.
- Providing a multi-protocol tunneling solution beyond HTTP(S).
- HTTP(S) 이외의 멀티 프로토콜 터널링 솔루션을 지향하지 않습니다.

These may evolve over time as the project matures. / 프로젝트 성숙도에 따라 이 범위는 향후 달라질 수 있습니다.

## 3. Architecture overview / 아키텍처 개요

At a high level, HopGate consists of the following components. / 높은 수준에서 HopGate는 다음과 같은 컴포넌트로 구성됩니다.

- **Public server / 공인 서버**: Terminates TLS, manages ACME, accepts DTLS connections, forwards HTTP(S) traffic.
- **공인 서버**: TLS 종단, ACME 인증서 관리, DTLS 연결 수립, HTTP(S) 트래픽 포워딩을 담당합니다.
- **Clients / 클라이언트**: Run inside private networks, connect to the server via DTLS, proxy HTTP requests to local services (127.0.0.1:PORT).
- **클라이언트**: 프라이빗 네트워크 내부에서 동작하며 DTLS로 서버에 연결하고, 서버가 전달한 HTTP 요청을 로컬 서비스(127.0.0.1:PORT)에 대신 보내고 응답을 다시 서버로 전달합니다.
- **Admin API / 관리 API**: REST endpoints for managing domains, API keys, and possibly future admin operations.
- **관리 API**: 도메인, API Key 및 향후 추가될 관리자 기능을 위한 REST 엔드포인트를 제공합니다.
- **Observability stack / 가시성 스택**: Metrics and logs intended to be scraped/collected by Prometheus, Loki, Grafana, etc.
- **가시성 스택**: 메트릭과 로그는 Prometheus, Loki, Grafana 등에서 수집·시각화하기 쉽도록 설계되어 있습니다.

For a more detailed diagram and explanation, refer to the architecture document. / 더 상세한 다이어그램과 설명은 아키텍처 문서를 참고해주세요.

- [`ARCHITECTURE.md`](../ARCHITECTURE.md)

## 4. Tech stack & languages / 기술 스택과 언어

- Implementation language: **Go**
- 구현 언어: **Go**
- Transport: **DTLS** over UDP
- 전송 계층: UDP 위의 **DTLS**
- Certificate management: **ACME** (e.g. Let's Encrypt)
- 인증서 관리: **ACME** (예: Let's Encrypt)
- Data store (planned for production): **PostgreSQL + ent**
- 데이터 저장소(프로덕션 계획): **PostgreSQL + ent**
- Observability: **Prometheus, Loki, Grafana-friendly logs and metrics**
- 가시성: **Prometheus, Loki, Grafana 친화적인 로그 및 메트릭**

Documentation and communication policy / 문서 및 커뮤니케이션 원칙:

- We aim for **Korean / English bilingual** docs where possible. / 가능하면 문서는 **한국어/영어 병기**를 지향합니다.
- Code comments and commit messages may be in English, but user-facing docs are typically ko/en. / 코드 주석과 커밋 메시지는 주로 영어를 사용하되, 사용자 대상 문서는 ko/en 병기를 유지하려고 합니다.

## 5. Project status & roadmap / 프로젝트 상태와 로드맵

HopGate is currently in an **experimental** stage; APIs and behavior may change at any time.
HopGate는 아직 **실험 단계(experimental)** 에 있으며, API 및 동작은 언제든지 변경될 수 있습니다.

High-level roadmap (subject to change) / 향후 로드맵(변경 가능):

- Stabilize the core DTLS tunnel and HTTP proxy behavior. / DTLS 터널과 HTTP 프록시 동작을 안정화합니다.
- Finalize the admin API and domain management flows. / 관리 API와 도메인 관리 플로우를 정리합니다.
- Wire up PostgreSQL + ent-based domain validation for production. / 프로덕션 환경을 위한 PostgreSQL + ent 기반 도메인 검증을 연동합니다.
- Harden security defaults and operational practices. / 보안 기본값과 운영 관행을 강화합니다.
- Improve observability (metrics, logs, dashboards). / 메트릭·로그·대시보드를 포함한 가시성을 개선합니다.

We track progress and milestones in a separate document. / 진행 현황과 마일스톤은 별도 문서로 관리합니다.

- [`progress.md`](../progress.md)

## 6. How to participate / 어떻게 참여할 수 있나요?

We welcome contributions from the community. / 커뮤니티의 다양한 기여를 환영합니다.

- **Issues**
  - Bug reports, feature requests, design discussions.
  - 버그 리포트, 기능 제안, 설계 관련 토론을 이슈에 남겨주세요.
- **Pull Requests**
  - Implementation of features, bug fixes, docs, refactoring, etc.
  - 기능 구현, 버그 수정, 문서 개선, 리팩터링 등은 PR로 보내주세요.
- **Discussions**
  - Q&A, open-ended ideas, RFC-style proposals.
  - Q&A, 아이디어 제안, RFC 스타일 제안을 Discussion에서 자유롭게 이야기해주세요.

For commit messages and code style, please refer to the commit message guideline in the repository. / 커밋 메시지와 코드 스타일은 저장소의 커밋 메시지 가이드를 참고해주세요.

- [`COMMIT_MESSAGE.md`](../COMMIT_MESSAGE.md)

## 7. Language policy / 언어 정책

- We use **English as the primary language** for code and interfaces, with **Korean/English bilingual documentation** where reasonable.
- 코드는 주로 **영어**를 사용하며, 문서는 가능한 범위에서 **한국어/영어 병기**를 유지합니다.
- Feel free to open Issues or Discussions in either Korean or English. / 이슈나 디스커션은 한국어 또는 영어 중 편한 언어로 작성해도 됩니다.

Thank you for your interest in HopGate. / HopGate에 관심을 가져주셔서 감사합니다.

We look forward to building this project together with the community. / 커뮤니티와 함께 이 프로젝트를 만들어 나가길 기대합니다.