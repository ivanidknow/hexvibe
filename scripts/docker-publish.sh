#!/usr/bin/env bash
set -euo pipefail

# Public image label (matches MCP / adapter HEXVIBE_RELEASE_VERSION).
HEXVIBE_VERSION="1.0.0"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE_TAG="hexvibe-ai:latest"

echo "[hexvibe] HexVibe v${HEXVIBE_VERSION} — building Docker image ${IMAGE_TAG}"
docker build -t "${IMAGE_TAG}" "${ROOT_DIR}"

echo "[hexvibe] Running internal image health test"
docker run --rm "${IMAGE_TAG}" /app/scripts/internal-test.sh

echo "[hexvibe] Done: ${IMAGE_TAG} (HexVibe v${HEXVIBE_VERSION})"
