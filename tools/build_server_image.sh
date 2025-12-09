. #!/usr/bin/env bash

set -euo pipefail

# Build hop-gate server image from Dockerfile.server.
# VERSION is derived from current git commit (7-char SHA).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="${SCRIPT_DIR}/.."
cd "${REPO_ROOT}"

VERSION="$(git rev-parse --short=7 HEAD 2>/dev/null || echo dev)"

# Default image name; can be overridden by first argument.
# Usage:
#   ./tools/build_server_image.sh                 # builds ghcr.io/dalbodeule/hop-gate:<hash> and :latest
#   ./tools/build_server_image.sh my/image/name   # builds my/image/name:<hash> and :latest
IMAGE_NAME="${1:-ghcr.io/dalbodeule/hop-gate}"

echo "Building hop-gate server image"
echo "  context : ${REPO_ROOT}"
echo "  image   : ${IMAGE_NAME}:${VERSION}"
echo "  version : ${VERSION}"

# Use docker buildx if available; fallback to docker build.
if command -v docker >/dev/null 2>&1 && docker buildx version >/dev/null 2>&1; then
  BUILD_CMD=(docker buildx build)
else
  BUILD_CMD=(docker build)
fi

# Optional environment variables:
#   PLATFORM=linux/amd64,linux/arm64   (for buildx)
#   PUSH=1                              (for buildx --push)

"${BUILD_CMD[@]}" \
  ${PLATFORM:+--platform "${PLATFORM}"} \
  -f Dockerfile.server \
  --build-arg VERSION="${VERSION}" \
  -t "${IMAGE_NAME}:${VERSION}" \
  -t "${IMAGE_NAME}:latest" \
  ${PUSH:+--push} \
  .