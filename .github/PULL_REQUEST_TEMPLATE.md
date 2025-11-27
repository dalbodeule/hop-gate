---
name: Pull Request
about: Pull Request template for the hop-gate repository / hop-gate 저장소를 위한 Pull Request 템플릿
---

## Summary / 개요

<!-- Briefly describe the changes in one or two sentences. / 변경 사항을 한두 문장으로 요약해주세요. -->

## Related Issues / 관련 이슈

- Closes #ISSUE_ID
- Related #ISSUE_ID

## Changes / 변경 내용

- [ ] Feature / 기능 추가
- [ ] Bug fix / 버그 수정
- [ ] Documentation / 문서 수정
- [ ] Tests / CI / 테스트 / CI
- [ ] Refactoring / 리팩터링
- [ ] Other: __________________ / 기타

Describe the concrete changes as a bullet list. / 구체적인 변경 사항을 bullet list로 정리해주세요.

## Testing / 테스트

Describe how you tested this change (manual/automated) and the results. / 수동/자동 테스트 방법과 결과를 적어주세요.

- [ ] `go test ./...`
- [ ] Other / 기타:

```bash
# Example / 예시:
go test ./...
```

## Compatibility / Migration / 호환성 / 마이그레이션

- [ ] Breaking change (affects existing usage) / Breaking change (기존 사용 방식에 영향을 줍니다)
- [ ] Database migration required / 데이터베이스 마이그레이션 필요
- [ ] Configuration changes/additions required / 설정값 변경 또는 추가 필요
- [ ] No compatibility impact / 기타 호환성 영향 없음

If necessary, describe how to migrate or update configuration. / 필요한 경우, 마이그레이션/설정 변경 방법을 설명해주세요.

## Checklist / 체크리스트

- [ ] Linked related issues. / 관련 이슈에 링크를 걸었습니다.
- [ ] Added/updated appropriate tests. / 적절한 테스트를 추가/수정했습니다.
- [ ] Updated documentation. / 문서를 최신 상태로 업데이트했습니다.
- [ ] Followed code style and lint rules. / 코드 스타일과 린트 규칙을 준수했습니다.
- [ ] Considered security and performance impact. / 보안/성능 영향에 대해 검토했습니다.