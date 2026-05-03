#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ENV_FILE="$SCRIPT_DIR/.env"
PROJECT_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
STAGING_ROOT="$PROJECT_ROOT/.delivery_tmp"
IDA_STAGING_DIR="$STAGING_ROOT/ida"
IDAPRO_STAGING_DIR="$STAGING_ROOT/idapro"
BINDIFF_STAGING_DIR="$STAGING_ROOT/bindiff"

if [ ! -f "$ENV_FILE" ]; then
  echo "missing $ENV_FILE, copy from .env.example first" >&2
  exit 1
fi

set -a
source "$ENV_FILE"
set +a

IMAGE_NAME="${VULNAGENT_IMAGE:-vulnagent-offline:latest}"
LOCAL_IDA_SOURCE="${LOCAL_IDA_SOURCE:-/Desktop/tools/IDA}"
LOCAL_IDA_HOME="${LOCAL_IDA_HOME:-/.idapro}"
LOCAL_BINDIFF_SOURCE="${LOCAL_BINDIFF_SOURCE:-/opt/bindiff}"

if [ ! -d "$LOCAL_IDA_SOURCE" ]; then
  echo "missing LOCAL_IDA_SOURCE directory: $LOCAL_IDA_SOURCE" >&2
  exit 1
fi

if [ ! -x "$LOCAL_IDA_SOURCE/ida" ]; then
  echo "missing executable ida in LOCAL_IDA_SOURCE: $LOCAL_IDA_SOURCE/ida" >&2
  exit 1
fi

if [ ! -x "$LOCAL_IDA_SOURCE/idat" ]; then
  echo "missing executable idat in LOCAL_IDA_SOURCE: $LOCAL_IDA_SOURCE/idat" >&2
  exit 1
fi

if [ ! -d "$LOCAL_IDA_SOURCE/plugins" ]; then
  echo "missing plugins directory in LOCAL_IDA_SOURCE: $LOCAL_IDA_SOURCE/plugins" >&2
  exit 1
fi

if [ ! -d "$LOCAL_IDA_HOME" ]; then
  echo "missing LOCAL_IDA_HOME directory: $LOCAL_IDA_HOME" >&2
  exit 1
fi

if [ ! -f "$LOCAL_IDA_HOME/ida.reg" ]; then
  echo "missing ida.reg in LOCAL_IDA_HOME: $LOCAL_IDA_HOME/ida.reg" >&2
  exit 1
fi

if [ ! -d "$LOCAL_IDA_HOME/plugins" ]; then
  echo "missing plugins directory in LOCAL_IDA_HOME: $LOCAL_IDA_HOME/plugins" >&2
  exit 1
fi

if [ ! -d "$LOCAL_BINDIFF_SOURCE" ]; then
  echo "missing LOCAL_BINDIFF_SOURCE directory: $LOCAL_BINDIFF_SOURCE" >&2
  exit 1
fi

if [ ! -x "$LOCAL_BINDIFF_SOURCE/bin/bindiff" ]; then
  echo "missing executable bindiff in LOCAL_BINDIFF_SOURCE: $LOCAL_BINDIFF_SOURCE/bin/bindiff" >&2
  exit 1
fi

if [ ! -x "$LOCAL_BINDIFF_SOURCE/bin/binexport2dump" ]; then
  echo "missing executable binexport2dump in LOCAL_BINDIFF_SOURCE: $LOCAL_BINDIFF_SOURCE/bin/binexport2dump" >&2
  exit 1
fi

cleanup() {
  rm -rf "$IDA_STAGING_DIR" "$IDAPRO_STAGING_DIR" "$BINDIFF_STAGING_DIR"
}
trap cleanup EXIT

rm -rf "$IDA_STAGING_DIR" "$IDAPRO_STAGING_DIR" "$BINDIFF_STAGING_DIR"
mkdir -p "$STAGING_ROOT"
cp -a "$LOCAL_IDA_SOURCE" "$IDA_STAGING_DIR"
cp -a "$LOCAL_IDA_HOME" "$IDAPRO_STAGING_DIR"
cp -a "$LOCAL_BINDIFF_SOURCE" "$BINDIFF_STAGING_DIR"

docker build -t "$IMAGE_NAME" "$PROJECT_ROOT"

echo "built $IMAGE_NAME"
