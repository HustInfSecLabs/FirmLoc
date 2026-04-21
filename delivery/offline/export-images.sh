#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ENV_FILE="$SCRIPT_DIR/.env"
OUTPUT_DIR="$SCRIPT_DIR/images"

if [ ! -f "$ENV_FILE" ]; then
  echo "missing $ENV_FILE, copy from .env.example first" >&2
  exit 1
fi

set -a
source "$ENV_FILE"
set +a

IMAGE_NAME="${VULNAGENT_IMAGE:-vulnagent-offline:latest}"
ARCHIVE_NAME=$(echo "$IMAGE_NAME" | tr '/:' '__').tar

mkdir -p "$OUTPUT_DIR"
docker save "$IMAGE_NAME" -o "$OUTPUT_DIR/$ARCHIVE_NAME"

echo "exported $IMAGE_NAME to $OUTPUT_DIR/$ARCHIVE_NAME"
