FROM python:3.10-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH=/opt/bindiff/bin:${PATH} \
    IDA32_PATH=/opt/ida/ida \
    IDA64_PATH=/opt/ida/ida \
    IDAT32_PATH=/opt/ida/idat \
    IDAT64_PATH=/opt/ida/idat \
    IDA_SERVICE_PORT=5000 \
    IDA_OUTPUT_ROOT=/data/ida_output \
    IDA_LOG_DIR=/data/ida_logs \
    VULNAGENT_CONFIG=/app/config/config.ini \
    VULNAGENT_DATA_ROOT=/data/AgentData

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    binwalk \
    squashfs-tools \
    p7zip-full \
    curl \
    ca-certificates \
    graphviz \
    file \
    libgl1 \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt
RUN python - <<'PY'
from pathlib import Path

skip = {
    "mouseinfo",
    "pyautogui",
    "pygetwindow",
    "pymsgbox",
    "pynput",
    "pyperclip",
    "pyrect",
    "pyscreeze",
    "pytweening",
}

src = Path("requirements.txt")
dst = Path("requirements.offline.txt")
lines = []
for line in src.read_text(encoding="utf-8").splitlines():
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        lines.append(line)
        continue

    package = stripped.split(";", 1)[0].split("==", 1)[0].strip().lower()
    if package in skip:
        continue
    lines.append(line)

dst.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
RUN pip install --upgrade pip && pip install -r requirements.offline.txt

COPY .delivery_tmp/ida /opt/ida
COPY .delivery_tmp/idapro /root/.idapro
COPY .delivery_tmp/bindiff /opt/bindiff
COPY . .

RUN mkdir -p /data/ida_output /data/ida_logs /data/AgentData \
    && /opt/ida/idapyswitch --force-path /usr/local/lib/libpython3.10.so.1.0 \
    && chmod +x /app/docker/offline/entrypoint.sh \
    && chmod +x /opt/bindiff/bin/bindiff /opt/bindiff/bin/binexport2dump

EXPOSE 8001 5000

ENTRYPOINT ["/app/docker/offline/entrypoint.sh"]