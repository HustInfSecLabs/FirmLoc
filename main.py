from fastapi import FastAPI, UploadFile, File, Form, status, Request, Query, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
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
from pathlib import Path
from enum import Enum
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from agent import (
    VulnAgent,
    run_repair_agent,
    ParameterCollector,
    HardcodedStringAuditor,
    WorkMode,
    SourceDiffAgent,
    SourceDiffParameterCollector,
)
from model import AgentModel
from config import config_manager
from db import (
    create_task,
    get_task_detail,
    init_db,
    list_task_events,
    list_task_findings,
    list_tasks,
    mark_task_failed,
    record_upload,
    start_task,
)
from log import logger
from utils.utils import get_binary_architecture, is_binary_file

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
SOURCE_DIFF_ROOT = os.path.join(path, "source_diff_sessions")
init_db()

jst = timezone(timedelta(hours=9))

parameter_collectors: Dict[str, ParameterCollector] = {}
source_diff_parameter_collectors: Dict[str, SourceDiffParameterCollector] = {}

# 默认工作模式配置（可通过环境变量或配置文件修改）
DEFAULT_WORK_MODE = WorkMode.REPRODUCTION

# 允许上传的文件类型（二进制或可执行文件）
ALLOWED_CONTENT_TYPES = {
    "application/octet-stream",
    "application/x-msdownload",
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-mach-binary",
}

# 常见固件文件后缀列表
FIRMWARE_EXTENSIONS = {
    ".bin",
    ".img",
    ".hex",
    ".ihex", ".mcs",
    ".elf",
    ".dfu",
    ".uf2",
    ".srec", ".s19", ".s28", ".s37",
    ".pat",
    ".ipsw",
    ".tar",
    ".jar"
}

CODE_REPAIR_EXTENSIONS = {
    ".c",
    ".cpp",
    ".h",
    ".hpp",
}

SOURCE_DIFF_EXTENSIONS = {
    ".c",
    ".cpp",
    ".cc",
    ".cxx",
    ".h",
    ".hpp",
    ".hh",
    ".hxx",
    ".js"
}

VALID_UPLOAD_ROLES = {"old", "new"}
VALID_ANALYSIS_MODES = {"auto", "firmware", "binary_pair"}


# 消息类型枚举
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
                    "content": "当前任务仍在执行，请稍候...",
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
        work_mode: str = None,
        analysis_mode: str = "auto",
    ) -> None:
        try:
            mode = work_mode or DEFAULT_WORK_MODE.value

            start_task(
                chat_id=chat_id,
                query=query,
                cve_id=params.get("cve_id"),
                cwe_id=params.get("cwe_id"),
                binary_filename=params.get("binary_filename"),
                vendor=params.get("vendor"),
                work_mode=mode,
                analysis_mode=analysis_mode,
                artifact_dir=os.path.join(path, str(chat_id)),
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
                analysis_mode=analysis_mode,
            )
            await agent.chat()
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("VulnAgent execution failed: %s", exc)
            try:
                mark_task_failed(chat_id, str(exc))
            except Exception as db_exc:  # pylint: disable=broad-except
                logger.warning("记录任务失败状态失败: %s", db_exc)
            await self._send_json(
                {
                    "chat_id": chat_id,
                    "type": "message",
                    "content": "系统执行失败，请稍后重试或联系管理员。",
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
                AgentModel("DeepSeek"),
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


def _normalize_upload_role(upload_role: Optional[str]) -> Optional[str]:
    normalized_role = (upload_role or "").strip().lower() or None
    if normalized_role not in {None, *VALID_UPLOAD_ROLES}:
        raise ValueError("upload_role 仅支持 old 或 new")
    return normalized_role


def _normalize_analysis_mode(analysis_mode: Optional[str]) -> str:
    normalized_mode = (analysis_mode or "auto").strip().lower() or "auto"
    if normalized_mode not in VALID_ANALYSIS_MODES:
        raise ValueError("analysis_mode 仅支持 auto、firmware 或 binary_pair")
    return normalized_mode




def _get_source_diff_session_dir(chat_id: str) -> str:
    return os.path.join(SOURCE_DIFF_ROOT, str(chat_id))


def _get_source_diff_output_dir(chat_id: str) -> str:
    return os.path.join(_get_source_diff_session_dir(chat_id), "source_diff")


def _list_source_diff_files(chat_id: str) -> List[Dict[str, Any]]:
    folder = _get_source_diff_session_dir(chat_id)
    if not os.path.exists(folder):
        raise HTTPException(status_code=404, detail="文件夹不存在")

    result: List[Dict[str, Any]] = []
    for filename in sorted(os.listdir(folder)):
        file_path = os.path.join(folder, filename)
        if not os.path.isfile(file_path):
            continue
        stat = os.stat(file_path)
        result.append(
            {
                "filename": filename,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime, tz=jst).isoformat(),
            }
        )
    return result


def _build_source_diff_runtime_message(
    chat_id: Optional[str],
    content: str,
    *,
    message_type: str = "message",
    status_value: str = "running",
    phase: str = "analysis",
    agent: str = "Source Diff Agent",
    tool: Optional[str] = None,
    is_last: bool = False,
    tool_status: Optional[Dict[str, Any]] = None,
    code: Optional[int] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "chat_id": chat_id,
        "is_last": is_last,
        "type": message_type,
        "content": content,
        "system_status": {
            "status": status_value,
            "agent": agent,
            "tool": tool,
            "phase": phase,
        },
        "tool_status": tool_status,
        "timestamp": datetime.now(tz=jst).isoformat(),
    }
    if code is not None:
        payload["code"] = code
    return payload


def _create_source_diff_sender(websocket: WebSocket, chat_id: str):
    async def _send(
        content: str,
        message_type: str = "message",
        status: str = "running",
        phase: str = "analysis",
        is_last: bool = False,
        tool_status: Optional[Dict[str, Any]] = None,
    ) -> None:
        await websocket.send_json(
            _build_source_diff_runtime_message(
                chat_id,
                content,
                message_type=message_type,
                status_value=status,
                phase=phase,
                is_last=is_last,
                tool_status=tool_status,
            )
        )

    return _send


async def _save_uploaded_file(chat_id: str, file: UploadFile, upload_role: Optional[str] = None) -> dict[str, Any]:
    filename = Path(file.filename).name
    ext = Path(filename).suffix.lower()
    if file.content_type not in ALLOWED_CONTENT_TYPES and ext not in FIRMWARE_EXTENSIONS:
        raise ValueError("文件类型不在白名单中")

    file_dir = os.path.join(path, str(chat_id))
    os.makedirs(file_dir, exist_ok=True)

    stored_name = f"{upload_role}_{filename}" if upload_role else filename
    save_path = os.path.join(file_dir, stored_name)
    if os.path.exists(save_path):
        raise FileExistsError("文件已存在")

    try:
        content = await file.read()
        with open(save_path, "wb") as output:
            output.write(content)
    except Exception as exc:  # pylint: disable=broad-except
        raise OSError(f"文件保存失败: {str(exc)}") from exc

    file_stat = os.stat(save_path)
    record_upload(
        chat_id=str(chat_id),
        filename=filename,
        saved_path=save_path,
        size_bytes=file_stat.st_size,
        content_type=file.content_type,
        upload_role=upload_role,
        artifact_dir=file_dir,
    )
    return {
        "id": stored_name,
        "name": filename,
        "created_at": int(time.time()),
        "bytes": file_stat.st_size,
        "upload_role": upload_role,
    }


async def _save_source_diff_file(chat_id: str, file: UploadFile) -> Dict[str, Any]:
    filename = Path(file.filename).name
    ext = Path(filename).suffix.lower()
    if ext not in SOURCE_DIFF_EXTENSIONS:
        raise ValueError("文件类型不在白名单中")

    session_dir = _get_source_diff_session_dir(chat_id)
    os.makedirs(session_dir, exist_ok=True)
    save_path = os.path.join(session_dir, filename)
    if os.path.exists(save_path):
        raise FileExistsError("文件已存在")

    try:
        content = await file.read()
        with open(save_path, "wb") as output:
            output.write(content)
    except Exception as exc:  # pylint: disable=broad-except
        raise OSError(f"文件保存失败: {str(exc)}") from exc

    file_stat = os.stat(save_path)
    return {
        "id": filename,
        "name": filename,
        "created_at": int(time.time()),
        "bytes": file_stat.st_size,
    }


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    for error in exc.errors():
        if error.get("type") == "value_error.file.size":
            return JSONResponse(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content={"code": 413, "msg": "超过单文件10MB限制", "data": None},
            )
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"code": 400, "msg": "请求参数错误", "data": None},
    )


@app.post("/v1/tasks")
async def create_task_endpoint(
    chat_id: Optional[str] = Form(default=None),
    query: Optional[str] = Form(default=None),
    cve_id: Optional[str] = Form(default=None),
    cwe_id: Optional[str] = Form(default=None),
    binary_filename: Optional[str] = Form(default=None),
    vendor: Optional[str] = Form(default=None),
    work_mode: Optional[str] = Form(default=None),
    analysis_mode: Optional[str] = Form(default="auto"),
):
    normalized_chat_id = (chat_id or f"task_{uuid.uuid4().hex[:12]}").strip()
    try:
        normalized_analysis_mode = _normalize_analysis_mode(analysis_mode)
    except ValueError as exc:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"code": 400, "msg": str(exc), "data": None},
        )

    artifact_dir = os.path.join(path, normalized_chat_id)
    os.makedirs(artifact_dir, exist_ok=True)
    task = create_task(
        chat_id=normalized_chat_id,
        query=(query or None),
        cve_id=(cve_id or None),
        cwe_id=(cwe_id or None),
        binary_filename=(binary_filename or None),
        vendor=(vendor or None),
        work_mode=(work_mode or None),
        analysis_mode=normalized_analysis_mode,
        artifact_dir=artifact_dir,
    )
    return {
        "code": 0,
        "msg": "创建成功",
        "data": task,
    }


@app.post("/v1/files")
async def upload_file(
    file: UploadFile = File(..., max_size=10 * 1024 * 1024),
    chat_id: str = Form(...),
    upload_role: Optional[str] = Form(default=None),
):
    try:
        normalized_role = _normalize_upload_role(upload_role)
        payload = await _save_uploaded_file(chat_id, file, normalized_role)
    except ValueError as exc:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"code": 400, "msg": str(exc), "data": None},
        )
    except FileExistsError as exc:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"code": 400, "msg": str(exc), "data": None},
        )
    except OSError as exc:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"code": 500, "msg": str(exc), "data": None},
        )
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning("记录上传任务失败: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"code": 500, "msg": f"文件上传失败: {str(exc)}", "data": None},
        )

    return {
        "code": 0,
        "msg": "上传成功",
        "data": payload,
    }


@app.post("/v1/tasks/{chat_id}/files/{upload_role}")
async def upload_task_role_file(
    chat_id: str,
    upload_role: str,
    file: UploadFile = File(..., max_size=10 * 1024 * 1024),
):
    try:
        normalized_role = _normalize_upload_role(upload_role)
        payload = await _save_uploaded_file(chat_id, file, normalized_role)
    except ValueError as exc:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"code": 400, "msg": str(exc), "data": None},
        )
    except FileExistsError as exc:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"code": 400, "msg": str(exc), "data": None},
        )
    except OSError as exc:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"code": 500, "msg": str(exc), "data": None},
        )
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning("记录上传任务失败: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"code": 500, "msg": f"文件上传失败: {str(exc)}", "data": None},
        )

    return {
        "code": 0,
        "msg": "上传成功",
        "data": payload,
    }


@app.post("/v1/sourceDiff/files")
async def upload_source_diff_file(
    file: UploadFile = File(..., max_size=10 * 1024 * 1024),
    chat_id: str = Form(...),
):
    try:
        payload = await _save_source_diff_file(chat_id, file)
    except ValueError as exc:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"code": 400, "msg": str(exc), "data": None},
        )
    except FileExistsError as exc:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"code": 400, "msg": str(exc), "data": None},
        )
    except OSError as exc:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"code": 500, "msg": str(exc), "data": None},
        )

    return {
        "code": 0,
        "msg": "上传成功",
        "data": payload,
    }


@app.get("/v1/sourceDiff/files")
async def list_source_diff_files(chat_id: str = Query(...)):
    return {"code": 0, "msg": "获取成功", "data": _list_source_diff_files(chat_id)}


@app.delete("/v1/sourceDiff/file")
async def delete_source_diff_file(chat_id: str = Query(...), filename: str = Query(...)):
    safe_name = Path(filename).name
    file_path = os.path.join(_get_source_diff_session_dir(chat_id), safe_name)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="文件不存在")
    os.remove(file_path)
    return {"code": 0, "msg": "删除成功"}


@app.post("/v1/hardcode_audit")
async def hardcode_audit(
    file: UploadFile = File(None, max_size=10 * 1024 * 1024),
    chat_id: str = Form(default=None),
    file_path: str = Form(default=None),
):
    """对单个二进制进行硬编码字符串审计。"""

    if not file and not file_path:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"code": 400, "msg": "缺少文件或文件路径", "data": None},
        )

    audit_chat_id = chat_id or f"stringaudit_{int(time.time())}"
    target_path: Optional[str] = None

    if file_path:
        candidate = Path(file_path)
        if not candidate.is_absolute():
            candidate = Path(path) / file_path
        if not candidate.exists():
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"code": 400, "msg": "file_path 不存在", "data": None},
            )
        target_path = str(candidate.resolve())
    else:
        filename = Path(file.filename).name
        ext = Path(filename).suffix.lower()
        if file.content_type not in ALLOWED_CONTENT_TYPES and ext not in FIRMWARE_EXTENSIONS:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"code": 400, "msg": "文件类型不在白名单中", "data": None},
            )

        file_dir = os.path.join(path, str(audit_chat_id))
        os.makedirs(file_dir, exist_ok=True)
        save_path = os.path.join(file_dir, filename)

        try:
            content = await file.read()
            with open(save_path, "wb") as output:
                output.write(content)
        except Exception as exc:  # pylint: disable=broad-except
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"code": 500, "msg": f"文件保存失败: {str(exc)}", "data": None},
            )
        target_path = save_path

    is_jar = target_path and target_path.lower().endswith('.jar')
    if not target_path or (not is_jar and not is_binary_file(target_path)):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"code": 400, "msg": "文件不是可识别的二进制/可执行文件或JAR文件", "data": None},
        )

    try:
        auditor = HardcodedStringAuditor()
        result = await auditor.audit(
            target_path,
            chat_id=audit_chat_id,
            ida_version=None if is_jar else get_binary_architecture(target_path),
        )
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("硬编码字符串审计失败: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"code": 500, "msg": f"字符串审计失败: {str(exc)}", "data": None},
        )

    return {
        "code": 0,
        "msg": "字符串审计完成",
        "data": result,
    }


@app.websocket("/v1/chat")
async def chat(websocket: WebSocket):
    session = WebSocketChatSession(websocket)
    await session.run()


@app.websocket("/v1/sourceDiff/analyze")
async def source_diff_ws(websocket: WebSocket):
    await websocket.accept()
    chat_id: Optional[str] = None

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send_json(
                    _build_source_diff_runtime_message(
                        chat_id,
                        "Invalid JSON",
                        message_type="error",
                        status_value="failed",
                        phase="parameter_collection",
                        code=400,
                    )
                )
                continue

            if message.get("type") != "message":
                await websocket.send_json(
                    _build_source_diff_runtime_message(
                        chat_id,
                        "Unsupported message type",
                        message_type="error",
                        status_value="failed",
                        phase="parameter_collection",
                        code=400,
                    )
                )
                continue

            incoming_chat_id = str(message.get("chat_id", "")).strip()
            if not incoming_chat_id:
                await websocket.send_json(
                    _build_source_diff_runtime_message(
                        None,
                        "Missing chat_id in message",
                        message_type="error",
                        status_value="failed",
                        phase="parameter_collection",
                        code=400,
                        is_last=True,
                    )
                )
                continue

            content = str(message.get("content") or "").strip()
            if not content:
                await websocket.send_json(
                    _build_source_diff_runtime_message(
                        incoming_chat_id,
                        "Missing content in message",
                        message_type="error",
                        status_value="failed",
                        phase="parameter_collection",
                        code=400,
                    )
                )
                continue

            if chat_id is None:
                chat_id = incoming_chat_id
            elif chat_id != incoming_chat_id:
                await websocket.send_json(
                    _build_source_diff_runtime_message(
                        chat_id,
                        "Chat session mismatch",
                        message_type="error",
                        status_value="failed",
                        phase="parameter_collection",
                        code=409,
                    )
                )
                continue

            session_dir = _get_source_diff_session_dir(chat_id)
            os.makedirs(session_dir, exist_ok=True)

            collector = source_diff_parameter_collectors.get(chat_id)
            if collector is None:
                collector = SourceDiffParameterCollector(
                    chat_id=chat_id,
                    base_dir=session_dir,
                    send_callback=lambda payload: websocket.send_json(payload),
                    chat_model=AgentModel("DeepSeek"),
                    allowed_extensions=SOURCE_DIFF_EXTENSIONS,
                )
                source_diff_parameter_collectors[chat_id] = collector
            else:
                collector.update_sender(lambda payload: websocket.send_json(payload))

            result = await collector.handle_message(content)
            if not result.get("ready"):
                continue

            params = result.get("parameters", {})
            file1_path = os.path.join(session_dir, params["file1"])
            file2_path = os.path.join(session_dir, params["file2"])
            if not os.path.exists(file1_path) or not os.path.exists(file2_path):
                await websocket.send_json(
                    _build_source_diff_runtime_message(
                        chat_id,
                        "指定文件不存在，请重新确认 file1/file2。",
                        message_type="error",
                        status_value="failed",
                        phase="parameter_collection",
                        is_last=True,
                    )
                )
                source_diff_parameter_collectors.pop(chat_id, None)
                break

            sender = _create_source_diff_sender(websocket, chat_id)
            await sender(
                "开始执行源码 diff 分析。",
                message_type="message",
                status="running",
                phase="analysis",
            )

            try:
                agent = SourceDiffAgent(chat_id=chat_id, workspace_dir=session_dir)
                await agent.execute(
                    file1_path=file1_path,
                    file2_path=file2_path,
                    cve_id=params.get("cve_id"),
                    cwe=params.get("cwe"),
                    cve_details=params.get("cve_details"),
                    send_message=sender,
                )
                await sender(
                    "Source Diff 流程结束。",
                    message_type="message",
                    status="completed",
                    phase="analysis",
                    is_last=True,
                )
            except Exception as exc:  # pylint: disable=broad-except
                logger.error("Source Diff analyze failed: %s", exc)
                await websocket.send_json(
                    _build_source_diff_runtime_message(
                        chat_id,
                        f"运行错误：{str(exc)}",
                        message_type="error",
                        status_value="failed",
                        phase="analysis",
                        is_last=True,
                    )
                )
            finally:
                source_diff_parameter_collectors.pop(chat_id, None)
            break
    except WebSocketDisconnect:
        logger.info("Source Diff WebSocket disconnected")
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("Source Diff WebSocket error: %s", exc)
        if websocket.client_state == WebSocketState.CONNECTED:
            with contextlib.suppress(Exception):
                await websocket.send_json(
                    _build_source_diff_runtime_message(
                        chat_id,
                        f"运行错误：{str(exc)}",
                        message_type="error",
                        status_value="failed",
                        phase="analysis",
                        is_last=True,
                    )
                )
    finally:
        if chat_id is not None:
            source_diff_parameter_collectors.pop(chat_id, None)
        if websocket.client_state == WebSocketState.CONNECTED:
            with contextlib.suppress(Exception):
                await websocket.close()




@app.get("/v1/chat_list")
async def get_chat_list():
    try:
        chat_list = list_tasks()
        if chat_list is not None:
            return {
                "code": 0,
                "msg": "获取成功",
                "data": chat_list,
            }
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning("从数据库读取聊天列表失败，回退到目录扫描: %s", exc)

    chat_list = []
    for chat_id in os.listdir(path):
        if chat_id == "source_diff_sessions":
            continue
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

    return {
        "code": 0,
        "msg": "获取成功",
        "data": chat_list,
    }


@app.get("/v1/tasks/{chat_id}")
async def get_task(chat_id: str):
    task = get_task_detail(chat_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    return {
        "code": 0,
        "msg": "获取成功",
        "data": task,
    }


@app.get("/v1/tasks/{chat_id}/events")
async def get_task_events(chat_id: str, limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0)):
    task = get_task_detail(chat_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    return {
        "code": 0,
        "msg": "获取成功",
        "data": list_task_events(chat_id, limit=limit, offset=offset),
    }


@app.get("/v1/tasks/{chat_id}/findings")
async def get_task_findings(chat_id: str, limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0)):
    task = get_task_detail(chat_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    return {
        "code": 0,
        "msg": "获取成功",
        "data": list_task_findings(chat_id, limit=limit, offset=offset),
    }


@app.post("/v1/codeRepair/files")
async def upload_code_repair_file(
    file: UploadFile = File(..., max_size=10 * 1024 * 1024),
    chat_id: str = Form(...),
):
    filename = Path(file.filename).name
    ext = Path(filename).suffix.lower()

    if ext not in CODE_REPAIR_EXTENSIONS:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"code": 400, "msg": "文件类型不在白名单中", "data": None},
        )

    file_dir = os.path.join(path, str(chat_id))
    os.makedirs(file_dir, exist_ok=True)

    save_path = os.path.join(file_dir, filename)
    if os.path.exists(save_path):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"code": 400, "msg": "文件已存在", "data": None},
        )

    try:
        content = await file.read()
        with open(save_path, "wb") as output:
            output.write(content)
    except Exception as exc:  # pylint: disable=broad-except
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"code": 500, "msg": f"文件保存失败: {str(exc)}", "data": None},
        )

    file_stat = os.stat(save_path)
    return {
        "code": 0,
        "msg": "上传成功",
        "data": {
            "id": filename,
            "created_at": int(time.time()),
            "bytes": file_stat.st_size,
        },
    }


@app.get("/v1/codeRepair/files")
async def list_files(chat_id: str = Query(...)):
    folder = os.path.join(path, str(chat_id))
    if not os.path.exists(folder):
        raise HTTPException(404, detail="文件夹不存在")
    result = []
    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)
        if os.path.isfile(file_path):
            stat = os.stat(file_path)
            result.append(
                {
                    "filename": filename,
                    "size": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime, tz=jst).isoformat(),
                }
            )
    return {"code": 0, "msg": "获取成功", "data": result}


@app.delete("/v1/codeRepair/file")
async def delete_file(chat_id: str = Query(...), filename: str = Query(...)):
    file_path = os.path.join(path, str(chat_id), filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="文件不存在")
    os.remove(file_path)
    return {"code": 0, "msg": "删除成功"}


@app.websocket("/v1/codeRepair/repair")
async def code_repair_ws(websocket: WebSocket):
    await websocket.accept()

    try:
        data = await websocket.receive_text()
        message = json.loads(data)
        chat_id = message.get("chat_id")

        if not chat_id:
            await websocket.send_json({
                "chat_id": None,
                "is_last": True,
                "type": "error",
                "content": "Missing chat_id in message",
                "message": "Missing chat_id in message",
                "code": 400,
                "system_status": {
                    "status": "failed",
                    "agent": "Code Repair Agent",
                    "tool": None,
                    "phase": "repair",
                },
                "tool_status": None,
                "timestamp": datetime.now(tz=jst).isoformat(),
            })
            return

        base_dir = os.path.join(path, str(chat_id))
        os.makedirs(base_dir, exist_ok=True)

        async def send_message_async(content: str, type: str = "message"):
            try:
                await websocket.send_json(
                    {
                        "chat_id": chat_id,
                        "is_last": False,
                        "type": type,
                        "content": content,
                        "system_status": {
                            "status": "running",
                            "agent": "Code Repair Agent",
                            "tool": None,
                            "phase": "repair",
                        },
                        "tool_status": None,
                        "timestamp": datetime.now(tz=jst).isoformat(),
                    }
                )
            except Exception as exc:  # pylint: disable=broad-except
                logger.error(f"WebSocket send failed: {exc}")

        loop = asyncio.get_event_loop()

        try:
            future = loop.run_in_executor(
                None,
                lambda: run_repair_agent(
                    base_dir,
                    lambda **kwargs: asyncio.run_coroutine_threadsafe(send_message_async(**kwargs), loop),
                ),
            )
            success, result_msg = await future

            await websocket.send_json(
                {
                    "chat_id": chat_id,
                    "is_last": True,
                    "type": "message",
                    "content": result_msg if success else f"执行失败：{result_msg}",
                    "system_status": {
                        "status": "completed" if success else "failed",
                        "agent": "Code Repair Agent",
                        "tool": None,
                        "phase": "repair",
                    },
                    "tool_status": None,
                    "timestamp": datetime.now(tz=jst).isoformat(),
                }
            )

        except Exception as exc:  # pylint: disable=broad-except
            await websocket.send_json(
                {
                    "chat_id": chat_id,
                    "is_last": True,
                    "type": "error",
                    "content": f"运行错误：{str(exc)}",
                    "system_status": {
                        "status": "failed",
                        "agent": "Code Repair Agent",
                        "tool": None,
                        "phase": "repair",
                    },
                    "tool_status": None,
                    "timestamp": datetime.now(tz=jst).isoformat(),
                }
            )

        finally:
            await websocket.close()

    except Exception as exc:  # pylint: disable=broad-except
        logger.error(f"WebSocket error: {exc}")
        await websocket.close()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000)
