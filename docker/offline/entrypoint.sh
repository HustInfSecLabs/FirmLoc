#!/usr/bin/env bash
set -euo pipefail

APP_ROOT=/app
DEFAULT_CONFIG="$APP_ROOT/config/config.ini"
EXAMPLE_CONFIG="$APP_ROOT/config/config.ini.example"
CONFIG_PATH="${VULNAGENT_CONFIG:-$DEFAULT_CONFIG}"
VULNAGENT_PORT="${VULNAGENT_PORT:-8001}"

mkdir -p \
  "$(dirname "$CONFIG_PATH")" \
  "${IDA_OUTPUT_ROOT:-/data/ida_output}" \
  "${IDA_LOG_DIR:-/data/ida_logs}" \
  "${VULNAGENT_DATA_ROOT:-/data/HustAgentData}" \
  "$APP_ROOT/images" \
  "$APP_ROOT/log"

if [ ! -f "$CONFIG_PATH" ] && [ -f "$EXAMPLE_CONFIG" ]; then
  cp "$EXAMPLE_CONFIG" "$CONFIG_PATH"
fi

export VULNAGENT_CONFIG="$CONFIG_PATH"

cd "$APP_ROOT"

python agent/IDAService/app_linux.py &
IDA_PID=$!
uvicorn main:app --host 0.0.0.0 --port "$VULNAGENT_PORT" &
VULNAGENT_PID=$!

cleanup() {
  kill "$IDA_PID" "$VULNAGENT_PID" 2>/dev/null || true
  wait "$IDA_PID" "$VULNAGENT_PID" 2>/dev/null || true
}

trap cleanup INT TERM EXIT

wait -n "$IDA_PID" "$VULNAGENT_PID"
STATUS=$?
cleanup
exit "$STATUS"
