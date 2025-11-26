#!/usr/bin/env bash
set -euo pipefail

# 프로젝트 루트 기준으로 실행한다고 가정.
# 이 스크립트를 프로젝트 루트에서 실행하지 않는다면,
# 아래 BASE_DIR 를 적절히 조정하거나 `cd`를 추가하세요.
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$BASE_DIR"

echo "[ent] project root: $BASE_DIR"

# 1. ent 바이너리 체크
if ! command -v ent >/dev/null 2>&1; then
  echo "[ent] 'ent' CLI 가 설치되어 있지 않습니다."
  echo "      설치: go install entgo.io/ent/cmd/ent@latest"
  exit 1
fi

# 2. ./ent/schema/*.go 존재 확인
SCHEMA_DIR="$BASE_DIR/ent/schema"
if [ ! -d "$SCHEMA_DIR" ]; then
  echo "[ent] 스키마 디렉터리가 없습니다: $SCHEMA_DIR"
  exit 1
fi

shopt -s nullglob
SCHEMA_FILES=("$SCHEMA_DIR"/*.go)
shopt -u nullglob

if [ ${#SCHEMA_FILES[@]} -eq 0 ]; then
  echo "[ent] 스키마 파일(./ent/schema/*.go)이 없습니다."
  exit 1
fi

echo "[ent] schema files:"
for f in "${SCHEMA_FILES[@]}"; do
  echo "  - $f"
done

# 3. ent 코드 생성
echo "[ent] generating ent client from ./ent/schema"
ent generate ./ent/schema
echo "[ent] ent code generation complete."

echo "[ent] done."
