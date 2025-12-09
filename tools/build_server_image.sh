#!/bin/sh

# POSIX sh 버전의 hop-gate 서버 이미지 빌드 스크립트.
# VERSION 은 현재 git 커밋의 7글자 SHA 를 사용합니다.

set -eu

# 스크립트 위치 기준 리포 루트 계산
SCRIPT_DIR=$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)
REPO_ROOT="${SCRIPT_DIR}/.."
cd "${REPO_ROOT}"

# 현재 커밋 7글자 SHA, git 정보가 없으면 dev
VERSION=$(git rev-parse --short=7 HEAD 2>/dev/null || echo dev)

# 기본 이미지 이름 (첫 번째 인자로 override 가능)
# 예:
#   ./tools/build_server_image.sh
#   ./tools/build_server_image.sh my/image/name
IMAGE_NAME=${1:-ghcr.io/dalbodeule/hop-gate}

echo "Building hop-gate server image"
echo "  context : ${REPO_ROOT}"
echo "  image   : ${IMAGE_NAME}:${VERSION}"
echo "  version : ${VERSION}"

# docker buildx 사용 가능 여부 확인
if command -v docker >/dev/null 2>&1 && docker buildx version >/dev/null 2>&1; then
  BUILD_CMD="docker buildx build"
else
  BUILD_CMD="docker build"
fi

# 선택적 환경 변수:
#   PLATFORM=linux/amd64,linux/arm64   # buildx 용
#   PUSH=1                             # buildx --push

PLATFORM_ARGS=""
if [ "${PLATFORM-}" != "" ]; then
  PLATFORM_ARGS="--platform ${PLATFORM}"
fi

PUSH_ARGS=""
if [ "${PUSH-}" != "" ]; then
  PUSH_ARGS="--push"
fi

# 실제 빌드 실행
# shellcheck disable=SC2086
${BUILD_CMD} \
  ${PLATFORM_ARGS} \
  -f Dockerfile.server \
  --build-arg VERSION="${VERSION}" \
  -t "${IMAGE_NAME}:${VERSION}" \
  -t "${IMAGE_NAME}:latest" \
  ${PUSH_ARGS} \
  .