from fastapi import FastAPI, UploadFile, File, Form, status, Request, Query, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.websockets import WebSocketState
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import os
import time
import uuid
import asyncio
import json
import contextlib
import shutil
from pathlib import Path
from enum import Enum
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, cast

from agent import (
    VulnAgent,
    ParameterCollector,
    WorkMode,
)
from config import config_manager
from db import (
    create_task,
    get_platform_task,
    get_task_detail,
    init_db,
    list_platform_task_events,
    list_platform_task_findings,
    list_platform_tasks,
    list_task_events,
    list_task_findings,
    list_tasks,
    mark_task_cancelled,
    mark_task_failed,
    record_upload,
    start_task,
)
from log import logger

app = FastAPI()

cors_allow_origins = os.getenv("CORS_ALLOW_ORIGINS", "*")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in cors_allow_origins.split(",") if origin.strip()] or ["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

if not os.path.exists("images"):
    os.makedirs("images")
app.mount("/static/images", StaticFiles(directory="images"), name="static")

path = config_manager.config["result.path"]["savedir"]
SHARED_DATA_DIRNAME = "HustAgentData"
VULNAGENT_AGENT_ID = "vulnagent"
init_db()

jst = timezone(timedelta(hours=9))

parameter_collectors: Dict[str, ParameterCollector] = {}

DEFAULT_WORK_MODE = WorkMode.REPRODUCTION

ALLOWED_CONTENT_TYPES = {
    "application/octet-stream",
    "application/x-msdownload",
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-mach-binary",
}

FIRMWARE_EXTENSIONS = {
    ".bin",
    ".img",
    ".zip",
    ".hex",
    ".ihex", ".mcs",
    ".elf",
    ".fw",
    ".dfu",
    ".uf2",
    ".srec", ".s19", ".s28", ".s37",
    ".pat",
    ".ipsw",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".jar",
    ".rar"
}

VALID_UPLOAD_ROLES = {"old", "new"}
VALID_ANALYSIS_MODES = {"auto", "firmware", "binary_pair"}
PLATFORM_SOURCE = "deepaudit_extension"
PLATFORM_MAX_UPLOAD_BYTES = 6000 * 1024 * 1024
UPLOAD_STREAM_CHUNK_BYTES = 1024 * 1024
platform_task_runners: Dict[str, asyncio.Task] = {}


class PlatformTaskCreateRequest(BaseModel):
    external_task_id: str
    owner_id: str
    name: str
    description: Optional[str] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    binary_filename: Optional[str] = None
    vendor: Optional[str] = None
    work_mode: Optional[str] = None
    analysis_mode: str = "auto"
    source: str = PLATFORM_SOURCE


class MessageType(str, Enum):
    HEADER1 = "header1"
    HEADER2 = "header2"
    CONTENT = "content"
    COMMAND = "command"


class WebSocketChatSession:
    """Manage a single websocket session including heartbeat and agent lifecycle."""

    PING_INTERVAL = 20
    PONG_TIMEOUT = 600

    def __init__(self, websocket: WebSocket) -> None:
        self.websocket = websocket
        self.chat_id: Optional[str] = None
        self.collector: Optional[ParameterCollector] = None
        self.last_activity = time.monotonic()
        self._send_lock = asyncio.Lock()
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._agent_task: Optional[asyncio.Task] = None
        self._closing = asyncio.Event()
        self._websocket_available = True

    def _can_send(self, payload: Optional[Dict[str, Any]] = None) -> bool:
        if not self._websocket_available:
            return False
        if self.websocket.client_state != WebSocketState.CONNECTED:
            return False
        if self._closing.is_set() and (payload or {}).get("type") != "close":
            return False
        return True

    async def run(self) -> None:
        await self.websocket.accept()
        logger.info("WebSocket connection accepted")
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        try:
            async for raw in self.websocket.iter_text():
                await self._handle_raw_message(raw)
        except WebSocketDisconnect:
            logger.info("WebSocket disconnected by client")
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("WebSocket session error: %s", exc)
            await self._send_json({"type": "error", "message": "internal_error"})
        finally:
            await self._shutdown()

    async def _handle_raw_message(self, raw: str) -> None:
        self.last_activity = time.monotonic()
        try:
            message = json.loads(raw)
        except json.JSONDecodeError:
            await self._send_json({"type": "error", "code": 400, "message": "Invalid JSON"})
            return

        msg_type = message.get("type")
        if msg_type == "pong":
            return
        if msg_type == "ping":
            await self._send_json({"type": "pong"})
            return

        if msg_type != "message":
            await self._send_json({"type": "error", "code": 400, "message": "Unsupported message type"})
            return

        chat_id = str(message.get("chat_id", "")).strip()
        content = (message.get("content") or "").strip()

        if not chat_id or not content:
            await self._send_json({"type": "error", "code": 400, "message": "Missing chat_id or content"})
            return

        if self.chat_id is None:
            self.chat_id = chat_id
        elif self.chat_id != chat_id:
            await self._send_json({"type": "error", "code": 409, "message": "Chat session mismatch"})
            return

        collector = self._ensure_collector(chat_id)
        result = await collector.handle_message(content)

        if not result.get("ready"):
            return

        if self._agent_task and not self._agent_task.done():
            await self._send_json(
                {
                    "chat_id": chat_id,
                    "type": "message",
                    "content": "The task is still running, please wait...",
                    "system_status": {
                        "status": "BUSY",
                        "agent": "VulnAgent",
                        "tool": None,
                    },
                    "tool_status": None,
                    "is_last": False,
                }
            )
            return

        params = result.get("parameters", {})
        merged_query = result.get("query") or content
        work_mode = result.get("work_mode", DEFAULT_WORK_MODE.value)
        analysis_mode = _normalize_analysis_mode(params.get("analysis_mode"))
        parameter_collectors.pop(chat_id, None)
        self._agent_task = asyncio.create_task(
            self._run_agent(chat_id, merged_query, params, work_mode, analysis_mode)
        )

    async def _run_agent(
        self,
        chat_id: str,
        query: str,
        params: Dict[str, Any],
        work_mode: Optional[str] = None,
        analysis_mode: str = "auto",
    ) -> None:
        try:
            mode = work_mode or DEFAULT_WORK_MODE.value

            anonymous_owner_id = _normalize_owner_id(None)
            start_task(
                chat_id=chat_id,
                query=query,
                cve_id=params.get("cve_id"),
                cwe_id=params.get("cwe_id"),
                binary_filename=params.get("binary_filename"),
                vendor=params.get("vendor"),
                work_mode=mode,
                analysis_mode=analysis_mode,
                artifact_dir=_get_platform_task_dir_for_owner(anonymous_owner_id, chat_id),
                config={"parameters": params},
            )
            agent = VulnAgent(
                chat_id,
                query,
                self.websocket,
                cve_id=params.get("cve_id"),
                cwe_id=params.get("cwe_id"),
                binary_filename=params.get("binary_filename"),
                vendor=params.get("vendor"),
                work_mode=mode,
                config_dir=str(_task_artifact_dir(anonymous_owner_id, chat_id).parent),
                analysis_mode=analysis_mode,
            )
            await agent.chat()
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("VulnAgent execution failed: %s", exc)
            try:
                mark_task_failed(chat_id, str(exc))
            except Exception as db_exc:  # pylint: disable=broad-except
                logger.warning("Failed to record task failure status: %s", db_exc)
            await self._send_json(
                {
                    "chat_id": chat_id,
                    "type": "message",
                    "content": "System execution failed, please retry later or contact an administrator.",
                    "system_status": {
                        "status": "ERROR",
                        "agent": "VulnAgent",
                        "tool": None,
                    },
                    "tool_status": None,
                    "is_last": True,
                }
            )
        finally:
            self._agent_task = None
            self.collector = None

    def _ensure_collector(self, chat_id: str) -> ParameterCollector:
        collector = parameter_collectors.get(chat_id)
        if collector is None:
            task_detail = get_task_detail(chat_id)
            task_work_mode = (task_detail or {}).get("work_mode") or DEFAULT_WORK_MODE.value
            try:
                work_mode = WorkMode(task_work_mode)
            except ValueError:
                work_mode = DEFAULT_WORK_MODE

            collector = ParameterCollector(
                chat_id,
                self._send_json,
                config_manager.build_agent_model("parameter_agent"),
                work_mode=work_mode,
            )

            if task_detail:
                for field in collector.agent.required_fields:
                    value = task_detail.get(field)
                    if isinstance(value, str) and value.strip():
                        collector.parameters[field] = value.strip()

                optional_fields = ["vendor", "cve_id", "cwe_id"]
                for field in optional_fields:
                    value = task_detail.get(field)
                    if isinstance(value, str) and value.strip():
                        collector.optional_parameters[field] = value.strip()

                if not collector.original_query and task_detail.get("query"):
                    collector.original_query = str(task_detail["query"])

            parameter_collectors[chat_id] = collector
        else:
            collector.update_sender(self._send_json)
        self.collector = collector
        return collector

    async def _heartbeat_loop(self) -> None:
        try:
            while not self._closing.is_set():
                await asyncio.sleep(self.PING_INTERVAL)
                if time.monotonic() - self.last_activity > self.PONG_TIMEOUT:
                    logger.warning("Heartbeat timeout, closing WebSocket")
                    await self.websocket.close(code=1008)
                    break
                await self._send_json({"type": "ping"})
        except asyncio.CancelledError:
            logger.debug("Heartbeat loop cancelled")
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Heartbeat loop error: %s", exc)

    async def _send_json(self, payload: Dict[str, Any]) -> None:
        async with self._send_lock:
            if not self._can_send(payload):
                return
            try:
                await self.websocket.send_json(payload)
            except RuntimeError as exc:
                self._websocket_available = False
                logger.info("Skip websocket send after close: %s", exc)
                return
            except Exception as exc:  # pylint: disable=broad-except
                self._websocket_available = False
                logger.warning("WebSocket send failed: %s", exc)
                return

            msg_type = payload.get("type")
            if msg_type in {"ping", "pong", "close"}:
                logger.debug("WebSocket send: %s", payload)
                return
            logger.info("WebSocket send: %s", payload)

    async def _shutdown(self) -> None:
        if self._closing.is_set():
            return
        self._closing.set()
        self._websocket_available = self.websocket.client_state == WebSocketState.CONNECTED

        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._heartbeat_task

        if self._agent_task:
            self._agent_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._agent_task

        if self.chat_id is not None:
            parameter_collectors.pop(self.chat_id, None)

        if self._can_send({"type": "close"}):
            with contextlib.suppress(Exception):
                await self._send_json({"type": "close", "message": "Chat completed"})
                await self.websocket.close()
        else:
            self._websocket_available = False


def _normalize_platform_source(source: Optional[str]) -> str:
    normalized_source = (source or PLATFORM_SOURCE).strip().lower() or PLATFORM_SOURCE
    return normalized_source


def _shared_data_root() -> Path:
    shared_root_override = os.getenv("HUSTAGENT_DATA_ROOT")
    if shared_root_override:
        return Path(shared_root_override).expanduser().resolve()

    configured_root = config_manager.config.get("result.path", "savedir", fallback="").strip()
    if configured_root:
        configured_path = Path(configured_root).expanduser()
        if not configured_path.is_absolute():
            configured_path = (Path(__file__).resolve().parent / configured_path).resolve()
        return configured_path

    return Path.home() / SHARED_DATA_DIRNAME




def _normalize_owner_id(owner_id: Optional[str]) -> str:
    normalized_owner_id = (owner_id or "").strip()
    return normalized_owner_id or "anonymous"


def _user_storage_root(owner_id: str) -> Path:
    return _shared_data_root() / _normalize_owner_id(owner_id)


def _task_upload_dir(owner_id: str, task_id: str) -> Path:
    return _user_storage_root(owner_id) / "uploads" / VULNAGENT_AGENT_ID / str(task_id)


def _task_artifact_dir(owner_id: str, task_id: str) -> Path:
    return _user_storage_root(owner_id) / VULNAGENT_AGENT_ID / str(task_id)


def _task_input_dir(owner_id: str, task_id: str) -> Path:
    return _task_artifact_dir(owner_id, task_id) / "input"


def _task_output_dir(owner_id: str, task_id: str) -> Path:
    return _task_artifact_dir(owner_id, task_id) / "output"


def _initialize_platform_task_layout(owner_id: str, task_id: str, config: Dict[str, Any]) -> str:
    task_root = _task_artifact_dir(owner_id, task_id)
    input_dir = _task_input_dir(owner_id, task_id)
    output_dir = _task_output_dir(owner_id, task_id)

    task_root.mkdir(parents=True, exist_ok=True)
    input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    (input_dir / "config.json").write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
    return str(task_root)


def _reset_platform_task_storage(owner_id: str, task_id: str, config: Dict[str, Any]) -> str:
    task_root = _task_artifact_dir(owner_id, task_id)
    upload_root = _task_upload_dir(owner_id, task_id)

    if task_root.is_dir():
        shutil.rmtree(task_root)
    if upload_root.is_dir():
        shutil.rmtree(upload_root)

    return _initialize_platform_task_layout(owner_id, task_id, config)


def _get_platform_task_dir(task_id: str) -> str:
    return os.path.join(path, str(task_id))


def _get_platform_task_dir_for_owner(owner_id: str, task_id: str) -> str:
    return str(_task_artifact_dir(owner_id, task_id))


class _OfflineWebSocket:
    client_state = WebSocketState.DISCONNECTED

    async def send_json(self, _: Dict[str, Any]) -> None:  # pragma: no cover - defensive
        return None


async def _run_platform_task(task_id: str, query: str, payload: PlatformTaskCreateRequest) -> None:
    try:
        start_task(
            chat_id=task_id,
            query=query,
            cve_id=payload.cve_id,
            cwe_id=payload.cwe_id,
            binary_filename=payload.binary_filename,
            vendor=payload.vendor,
            work_mode=payload.work_mode or DEFAULT_WORK_MODE.value,
            analysis_mode=payload.analysis_mode,
            artifact_dir=_get_platform_task_dir_for_owner(payload.owner_id, task_id),
            config={
                "platform": {
                    "name": payload.name,
                    "description": payload.description,
                }
            },
            owner_id=payload.owner_id,
            external_task_id=payload.external_task_id,
            source=_normalize_platform_source(payload.source),
        )
        agent = VulnAgent(
            task_id,
            query,
            cast(WebSocket, _OfflineWebSocket()),
            cve_id=payload.cve_id,
            cwe_id=payload.cwe_id,
            binary_filename=payload.binary_filename,
            vendor=payload.vendor,
            work_mode=payload.work_mode or DEFAULT_WORK_MODE.value,
            config_dir=str(_task_artifact_dir(payload.owner_id, task_id).parent),
            analysis_mode=payload.analysis_mode,
        )
        await agent.chat()
    except asyncio.CancelledError:
        logger.info("Platform task cancelled: %s", task_id)
        mark_task_cancelled(task_id)
        raise
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("Platform task execution failed: %s", exc, exc_info=True)
        mark_task_failed(task_id, str(exc))
    finally:
        platform_task_runners.pop(task_id, None)


def _normalize_upload_role(upload_role: Optional[str]) -> Optional[str]:
    normalized_role = (upload_role or "").strip().lower() or None
    if normalized_role not in {None, *VALID_UPLOAD_ROLES}:
        raise ValueError("upload_role only supports old or new")
    return normalized_role


def _normalize_analysis_mode(analysis_mode: Optional[str]) -> str:
    normalized_mode = (analysis_mode or "auto").strip().lower() or "auto"
    if normalized_mode not in VALID_ANALYSIS_MODES:
        raise ValueError("analysis_mode only supports auto, firmware, or binary_pair")
    return normalized_mode


def _has_allowed_firmware_extension(filename: str) -> bool:
    normalized_name = filename.strip().lower()
    return any(normalized_name.endswith(ext) for ext in FIRMWARE_EXTENSIONS)



async def _save_uploaded_file(
    chat_id: str,
    file: UploadFile,
    upload_role: Optional[str] = None,
    owner_id: Optional[str] = None,
) -> dict[str, Any]:
    filename = Path(file.filename or "uploaded_file").name
    if file.content_type not in ALLOWED_CONTENT_TYPES and not _has_allowed_firmware_extension(filename):
        raise ValueError("File type is not in the allowlist")

    if owner_id:
        file_dir = _task_upload_dir(owner_id, chat_id)
    else:
        file_dir = Path(path) / str(chat_id)
    file_dir.mkdir(parents=True, exist_ok=True)

    stored_name = f"{upload_role}_{filename}" if upload_role else filename
    save_path = file_dir / stored_name
    if save_path.exists():
        raise FileExistsError("File already exists")

    try:
        with open(save_path, "wb") as output:
            total_size = 0
            while True:
                chunk = await file.read(UPLOAD_STREAM_CHUNK_BYTES)
                if not chunk:
                    break
                total_size += len(chunk)
                if total_size > PLATFORM_MAX_UPLOAD_BYTES:
                    raise ValueError(f"File size exceeds limit ({PLATFORM_MAX_UPLOAD_BYTES // (1024 * 1024)}MB)")
                output.write(chunk)
    except Exception as exc:  # pylint: disable=broad-except
        with contextlib.suppress(Exception):
            if save_path.exists():
                save_path.unlink()
        if isinstance(exc, ValueError):
            raise
        raise OSError(f"File save failed: {str(exc)}") from exc
    finally:
        with contextlib.suppress(Exception):
            await file.close()

    file_stat = os.stat(save_path)
    record_upload(
        chat_id=str(chat_id),
        filename=filename,
        saved_path=str(save_path),
        size_bytes=file_stat.st_size,
        content_type=file.content_type,
        upload_role=upload_role,
        artifact_dir=str(file_dir),
    )
    return {
        "id": stored_name,
        "name": filename,
        "created_at": int(time.time()),
        "bytes": file_stat.st_size,
        "upload_role": upload_role,
    }


def _platform_query_value(value: Optional[str]) -> Optional[str]:
    normalized = (value or "").strip()
    return normalized or None


async def _create_legacy_task(
    chat_id: Optional[str],
    query: Optional[str],
    cve_id: Optional[str],
    cwe_id: Optional[str],
    binary_filename: Optional[str],
    vendor: Optional[str],
    work_mode: Optional[str],
    analysis_mode: Optional[str],
) -> dict[str, Any]:
    normalized_chat_id = (chat_id or "").strip() or str(uuid.uuid4())
    normalized_analysis_mode = _normalize_analysis_mode(analysis_mode)
    task_dir = _get_platform_task_dir(normalized_chat_id)
    os.makedirs(task_dir, exist_ok=True)
    return await asyncio.to_thread(
        create_task,
        chat_id=normalized_chat_id,
        query=(query or "").strip() or None,
        cve_id=(cve_id or "").strip() or None,
        cwe_id=(cwe_id or "").strip() or None,
        binary_filename=(binary_filename or "").strip() or None,
        vendor=(vendor or "").strip() or None,
        work_mode=(work_mode or "").strip() or DEFAULT_WORK_MODE.value,
        analysis_mode=normalized_analysis_mode,
        artifact_dir=task_dir,
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "code": 422,
            "msg": "Request parameter validation failed",
            "data": exc.errors(),
        },
    )


@app.post("/v1/tasks")
async def create_legacy_task(
    chat_id: Optional[str] = Form(default=None),
    query: Optional[str] = Form(default=None),
    cve_id: Optional[str] = Form(default=None),
    cwe_id: Optional[str] = Form(default=None),
    binary_filename: Optional[str] = Form(default=None),
    vendor: Optional[str] = Form(default=None),
    work_mode: Optional[str] = Form(default=None),
    analysis_mode: Optional[str] = Form(default="auto"),
):
    try:
        task = await _create_legacy_task(
            chat_id,
            query,
            cve_id,
            cwe_id,
            binary_filename,
            vendor,
            work_mode,
            analysis_mode,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"code": 0, "msg": "Created successfully", "data": task}


@app.post("/v1/tasks/{chat_id}/files/{upload_role}")
async def upload_task_file(
    chat_id: str,
    upload_role: str,
    file: UploadFile = File(...),
):
    normalized_role = _normalize_upload_role(upload_role)
    try:
        payload = await _save_uploaded_file(chat_id, file, normalized_role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileExistsError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"code": 0, "msg": "Uploaded successfully", "data": payload}


@app.post("/v1/files")
async def upload_file(
    file: UploadFile = File(...),
    chat_id: str = Form(...),
    upload_role: Optional[str] = Form(default=None),
):
    normalized_role = _normalize_upload_role(upload_role)
    try:
        payload = await _save_uploaded_file(chat_id, file, normalized_role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileExistsError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"code": 0, "msg": "Uploaded successfully", "data": payload}


@app.post("/api/platform/tasks")
async def create_platform_task(payload: PlatformTaskCreateRequest):
    analysis_mode = _normalize_analysis_mode(payload.analysis_mode)
    normalized_source = _normalize_platform_source(payload.source)

    existing_task = await asyncio.to_thread(
        get_platform_task,
        owner_id=payload.owner_id,
        external_task_id=payload.external_task_id,
        source=normalized_source,
    )

    existing_task_id = existing_task.get("task_id") if existing_task else None
    task_id = str(existing_task_id) if existing_task_id else f"platform_{uuid.uuid4().hex[:20]}"
    platform_config = {"platform": {"name": payload.name, "description": payload.description}}
    if existing_task_id:
        task_dir = _reset_platform_task_storage(payload.owner_id, task_id, platform_config)
    else:
        task_dir = _initialize_platform_task_layout(payload.owner_id, task_id, platform_config)

    task = await asyncio.to_thread(
        create_task,
        chat_id=task_id,
        query=(payload.description or payload.name),
        cve_id=payload.cve_id,
        cwe_id=payload.cwe_id,
        binary_filename=payload.binary_filename,
        vendor=payload.vendor,
        work_mode=payload.work_mode or DEFAULT_WORK_MODE.value,
        analysis_mode=analysis_mode,
        artifact_dir=task_dir,
        config=platform_config,
        owner_id=payload.owner_id,
        external_task_id=payload.external_task_id,
        source=normalized_source,
    )
    return {"code": 0, "msg": "Created successfully", "data": task}


@app.post("/api/platform/tasks/{task_id}/files/{upload_role}")
async def upload_platform_task_file(
    task_id: str,
    upload_role: str,
    owner_id: str = Form(...),
    file: UploadFile = File(...),
):
    task = await asyncio.to_thread(get_platform_task, task_id=task_id, owner_id=owner_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")

    normalized_role = _normalize_upload_role(upload_role)
    try:
        payload = await _save_uploaded_file(task_id, file, normalized_role, owner_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileExistsError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return {"code": 0, "msg": "Uploaded successfully", "data": payload}


@app.post("/api/platform/tasks/{task_id}/start")
async def start_platform_task(task_id: str, owner_id: str = Form(...)):
    task = await asyncio.to_thread(get_platform_task, task_id=task_id, owner_id=owner_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    if task_id in platform_task_runners and not platform_task_runners[task_id].done():
        raise HTTPException(status_code=409, detail="Task is already running")

    payload = PlatformTaskCreateRequest(
        external_task_id=task.get("external_task_id") or "",
        owner_id=task.get("owner_id") or owner_id,
        name=task.get("name") or task_id,
        description=((task.get("config") or {}).get("platform") or {}).get("description") or task.get("query"),
        cve_id=task.get("cve_id"),
        cwe_id=task.get("cwe_id"),
        binary_filename=task.get("binary_filename"),
        vendor=task.get("vendor"),
        work_mode=task.get("work_mode"),
        analysis_mode=task.get("analysis_mode") or "auto",
        source=task.get("source") or PLATFORM_SOURCE,
    )
    runner = asyncio.create_task(_run_platform_task(task_id, task.get("query") or payload.name, payload))
    platform_task_runners[task_id] = runner
    return {"code": 0, "msg": "Started successfully", "data": {"task_id": task_id}}


@app.post("/api/platform/tasks/{task_id}/cancel")
async def cancel_platform_task(task_id: str, owner_id: str = Form(...)):
    task = await asyncio.to_thread(get_platform_task, task_id=task_id, owner_id=owner_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")

    runner = platform_task_runners.get(task_id)
    if runner and not runner.done():
        runner.cancel()
    else:
        await asyncio.to_thread(mark_task_cancelled, task_id)
    return {"code": 0, "msg": "Cancelled successfully", "data": {"task_id": task_id}}


@app.get("/api/platform/tasks")
async def list_platform_tasks_endpoint(
    owner_id: Optional[str] = Query(default=None),
    source: Optional[str] = Query(default=None),
):
    tasks = await asyncio.to_thread(
        list_platform_tasks,
        _platform_query_value(owner_id),
        _platform_query_value(source),
    )
    return {"code": 0, "msg": "Fetched successfully", "data": tasks}


@app.get("/api/platform/tasks/{task_id}")
async def get_platform_task_endpoint(task_id: str, owner_id: str = Query(...)):
    task = await asyncio.to_thread(get_platform_task, task_id=task_id, owner_id=owner_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"code": 0, "msg": "Fetched successfully", "data": task}


@app.get("/api/platform/tasks/{task_id}/events")
async def get_platform_task_events_endpoint(
    task_id: str,
    owner_id: str = Query(...),
    after_sequence: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    events = await asyncio.to_thread(
        list_platform_task_events,
        task_id=task_id,
        owner_id=owner_id,
        limit=limit,
        offset=offset,
        after_sequence=after_sequence,
    )
    if events is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"code": 0, "msg": "Fetched successfully", "data": events}


@app.get("/api/platform/tasks/{task_id}/findings")
async def get_platform_task_findings_endpoint(
    task_id: str,
    owner_id: str = Query(...),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    findings = await asyncio.to_thread(
        list_platform_task_findings,
        task_id=task_id,
        owner_id=owner_id,
        limit=limit,
        offset=offset,
    )
    if findings is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"code": 0, "msg": "Fetched successfully", "data": findings}


@app.websocket("/v1/chat")
async def websocket_endpoint(websocket: WebSocket):
    session = WebSocketChatSession(websocket)
    await session.run()

@app.get("/v1/chat_list")
async def get_chat_list():
    try:
        chat_list = await asyncio.to_thread(list_tasks)
        if chat_list is not None:
            return {
                "code": 0,
                "msg": "Fetched successfully",
                "data": chat_list,
            }
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning("Failed to read chat list from DB, fallback to directory scan: %s", exc)

    def _scan_chat_dirs():
        chat_list = []
        for chat_id in os.listdir(path):
            chat_dir = os.path.join(path, chat_id)
            if os.path.isdir(chat_dir):
                creation_timestamp = os.path.getctime(chat_dir)
                chat_list.append(
                    {
                        "chat_id": chat_id,
                        "chat_title": chat_id,
                        "create_time": datetime.fromtimestamp(creation_timestamp, tz=jst).isoformat(),
                    }
                )
        return chat_list

    chat_list = await asyncio.to_thread(_scan_chat_dirs)
    return {
        "code": 0,
        "msg": "Fetched successfully",
        "data": chat_list,
    }


@app.get("/v1/tasks/{chat_id}")
async def get_task(chat_id: str):
    task = await asyncio.to_thread(get_task_detail, chat_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return {
        "code": 0,
        "msg": "Fetched successfully",
        "data": task,
    }


@app.get("/v1/tasks/{chat_id}/events")
async def get_task_events(chat_id: str, limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0)):
    task = await asyncio.to_thread(get_task_detail, chat_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    events = await asyncio.to_thread(list_task_events, chat_id, limit, offset)
    return {
        "code": 0,
        "msg": "Fetched successfully",
        "data": events,
    }


@app.get("/v1/tasks/{chat_id}/findings")
async def get_task_findings(chat_id: str, limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0)):
    task = await asyncio.to_thread(get_task_detail, chat_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    findings = await asyncio.to_thread(list_task_findings, chat_id, limit, offset)
    return {
        "code": 0,
        "msg": "Fetched successfully",
        "data": findings,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8001)
