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

VULNAGENT_PORT="${VULNAGENT_PORT:-8001}"
IDA_SERVICE_PORT="${IDA_SERVICE_PORT:-5000}"

docker compose -f "$COMPOSE_FILE" ps
curl -fsS "http://127.0.0.1:${IDA_SERVICE_PORT}/health"
curl -fsS "http://127.0.0.1:${VULNAGENT_PORT}/docs" >/dev/null

echo "offline deployment check passed"
