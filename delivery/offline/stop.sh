#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
ENV_FILE="$SCRIPT_DIR/.env"

if [ ! -f "$ENV_FILE" ]; then
  echo "missing $ENV_FILE, copy from .env.example first" >&2
  exit 1
fi

set -a
source "$ENV_FILE"
set +a

docker compose -f "$COMPOSE_FILE" down
