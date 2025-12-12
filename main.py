from fastapi import FastAPI, UploadFile, File, Form, status, Request, Query, HTTPException, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import os
import time
import asyncio
import json
import contextlib
from pathlib import Path
from enum import Enum
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

from agent import VulnAgent, run_repair_agent, ParameterCollector
from model import AgentModel
from config import config_manager
from log import logger

app = FastAPI()

if not os.path.exists("images"):
    os.makedirs("images")
app.mount("/static/images", StaticFiles(directory="images"), name="static")

path = config_manager.config["result.path"]["savedir"]

jst = timezone(timedelta(hours=9))


parameter_collectors: Dict[str, ParameterCollector] = {}


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
            await self._send_json({
                "chat_id": chat_id,
                "type": "message",
                "content": "当前任务仍在执行，请稍候...",
                "system_status": {
                    "status": "BUSY",
                    "agent": "VulnAgent",
                    "tool": None
                },
                "tool_status": None,
                "is_last": False
            })
            return

        params = result.get("parameters", {})
        merged_query = result.get("query") or content
        parameter_collectors.pop(chat_id, None)
        self._agent_task = asyncio.create_task(self._run_agent(chat_id, merged_query, params))

    async def _run_agent(self, chat_id: str, query: str, params: Dict[str, Any]) -> None:
        try:
            agent = VulnAgent(
                chat_id,
                query,
                self.websocket,
                cve_id=params.get("cve_id"),
                binary_filename=params.get("binary_filename")
            )
            await agent.chat()
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("VulnAgent execution failed: %s", exc)
            await self._send_json({
                "chat_id": chat_id,
                "type": "message",
                "content": "系统执行失败，请稍后重试或联系管理员。",
                "system_status": {
                    "status": "ERROR",
                    "agent": "VulnAgent",
                    "tool": None
                },
                "tool_status": None,
                "is_last": True
            })
        finally:
            self._agent_task = None
            self.collector = None

    def _ensure_collector(self, chat_id: str) -> ParameterCollector:
        collector = parameter_collectors.get(chat_id)
        if collector is None:
            collector = ParameterCollector(chat_id, self._send_json, AgentModel("DeepSeek"))
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
            if self.websocket.client_state == WebSocketState.CONNECTED:
                await self.websocket.send_json(payload)
                logger.info("WebSocket send: %s", payload)

    async def _shutdown(self) -> None:
        if self._closing.is_set():
            return
        self._closing.set()

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

        if self.websocket.client_state == WebSocketState.CONNECTED:
            with contextlib.suppress(Exception):
                await self._send_json({"type": "close", "message": "Chat completed"})
                await self.websocket.close()

# 允许上传的文件类型（二进制或可执行文件）
ALLOWED_CONTENT_TYPES = {
    "application/octet-stream",  # 通用二进制文件类型
    "application/x-msdownload",  # Windows可执行文件 (.exe, .dll)
    "application/x-executable",  # Linux可执行文件
    "application/x-sharedlib",   # Linux共享库 (.so)
    "application/x-mach-binary", # macOS可执行文件
}

# 常见固件文件后缀列表
FIRMWARE_EXTENSIONS = {
    ".bin",  # raw binary firmware
    ".img",  # disk image firmware
    ".hex",  # Intel HEX text format 
    ".ihex", ".mcs",          # Intel HEX variants
    ".elf",  # ELF executables often used in embedded systems
    ".dfu",  # Device Firmware Update packages :contentReference[oaicite:2]{index=2}
    ".uf2",  # Microsoft UF2 bootloader format
    ".srec", ".s19", ".s28", ".s37",  # Motorola S-records
    ".pat",  # Cisco firmware images
    ".ipsw", # Apple firmware bundles
    ".tar"
}

CODE_REPAIR_EXTENSIONS = {
    ".c",
    ".cpp",
    ".h",
    ".hpp"
}

# 消息类型枚举
class MessageType(str, Enum):
    HEADER1 = "header1"
    HEADER2 = "header2"
    CONTENT = "content"
    COMMAND = "command"

# 自定义请求验证错误处理
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

@app.post("/v1/files")
async def upload_file(
    file: UploadFile = File(..., max_size=10 * 1024 * 1024),  # 10MB限制
    chat_id: str = Form(...)
):
    # 检查文件类型
    filename = Path(file.filename).name
    ext = Path(filename).suffix.lower()
    if file.content_type not in ALLOWED_CONTENT_TYPES and ext not in FIRMWARE_EXTENSIONS:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"code": 400, "msg": "文件类型不在白名单中", "data": None},
        )
    
    file_dir = os.path.join(path, str(chat_id))
    os.makedirs(file_dir, exist_ok=True)

    filename = Path(file.filename).name

    save_path = os.path.join(file_dir, filename)

    if os.path.exists(save_path):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"code": 400, "msg": "文件已存在", "data": None},
        )
    
    # 保存文件
    try:
        content = await file.read()
        with open(save_path, "wb") as f:
            f.write(content)
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"code": 500, "msg": f"文件保存失败: {str(e)}", "data": None},
        )
    
    # 获取文件信息
    file_stat = os.stat(save_path)


    # 构造响应数据
    return {
        "code": 0,
        "msg": "上传成功",
        "data": {
            "id": filename,  
            # "chat_id": chat_id,
            # "original_name": file.filename,
            # "saved_path": save_path,
            "created_at": int(time.time()),
            "bytes": file_stat.st_size,
        },
    }



@app.websocket("/v1/chat")
async def chat(websocket: WebSocket):
    session = WebSocketChatSession(websocket)
    await session.run()



@app.get("/v1/chat_list")
async def get_chat_list():
    """
    获取聊天列表
    # 时间格式：2025-04-15T15:30:45+09:00
    """
    chat_list = []
    for chat_id in os.listdir(path):
        chat_dir = os.path.join(path, chat_id)
        if os.path.isdir(chat_dir):
            creation_timestamp = os.path.getctime(chat_dir)
            chat_list.append({
                "chat_id": chat_id,
                "chat_title": chat_id,
                "create_time": datetime.fromtimestamp(creation_timestamp, tz=jst).isoformat(),
            })
    
    return {
        "code": 0,
        "msg": "获取成功",
        "data": chat_list
    }

@app.post("/v1/codeRepair/files")
async def upload_file(
    file: UploadFile = File(..., max_size=10 * 1024 * 1024),  # 10MB限制
    chat_id: str = Form(...)
):
    # 检查文件类型
    filename = Path(file.filename).name
    ext = Path(filename).suffix.lower()
    
    if ext not in CODE_REPAIR_EXTENSIONS:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"code": 400, "msg": "文件类型不在白名单中", "data": None},
        )
    
    file_dir = os.path.join(path, str(chat_id))
    os.makedirs(file_dir, exist_ok=True)

    filename = Path(file.filename).name
    save_path = os.path.join(file_dir, filename)

    if os.path.exists(save_path):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"code": 400, "msg": "文件已存在", "data": None},
        )
    
    # 保存文件
    try:
        content = await file.read()
        with open(save_path, "wb") as f:
            f.write(content)
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"code": 500, "msg": f"文件保存失败: {str(e)}", "data": None},
        )
    
    # 获取文件信息
    file_stat = os.stat(save_path)

    # 构造响应数据
    return {
        "code": 0,
        "msg": "上传成功",
        "data": {
            "id": filename,  
            # "chat_id": chat_id,
            # "original_name": file.filename,
            # "saved_path": save_path,
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
    for f in os.listdir(folder):
        path = os.path.join(folder, f)
        if os.path.isfile(path):
            stat = os.stat(path)
            result.append({
                "filename": f,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime, tz=jst).isoformat()
            })
    return {"code": 0, 
            "msg": "获取成功",
            "data": result}

@app.delete("/v1/codeRepair/file")
async def delete_file(chat_id: str = Query(...), filename: str = Query(...)):
    path = os.path.join(path, str(chat_id), filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="文件不存在")
    os.remove(path)
    return {"code": 0, 
            "msg": "删除成功"}

@app.websocket("/v1/codeRepair/repair")
async def code_repair_ws(websocket: WebSocket):
    await websocket.accept()
    
    try:
        # 等待客户端发送包含 chat_id 的消息
        data = await websocket.receive_text()
        message = json.loads(data)
        chat_id = message.get("chat_id")
        
        if not chat_id:
            await websocket.send_json({
                "error": "Missing chat_id in message",
                "code": 400
            })
            return
        
        base_dir = os.path.join(path, str(chat_id))
        os.makedirs(base_dir, exist_ok=True)

        async def send_message_async(content: str, type: str = "message"):
            try:
                await websocket.send_json({
                    "chat_id": chat_id,
                    "is_last": False,
                    "type": type,
                    "content": content,
                    "system_status": {},
                    "tool_status": None
                })
            except Exception as e:
                logger.error(f"WebSocket send failed: {e}")

        loop = asyncio.get_event_loop()

        try:
            future = loop.run_in_executor(
                None,
                lambda: run_repair_agent(
                    base_dir,
                    lambda **kwargs: asyncio.run_coroutine_threadsafe(send_message_async(**kwargs), loop)
                )
            )
            success, result_msg = await future

            # 结束消息，根据 success 判定状态
            await websocket.send_json({
                "chat_id": chat_id,
                "is_last": True,
                "type": "message",
                "content": result_msg if success else f"执行失败：{result_msg}",
                "system_status": {},
                "tool_status": None
            })

        except Exception as e:
            await websocket.send_json({
                "chat_id": chat_id,
                "is_last": True,
                "type": "error",
                "content": f"运行错误：{str(e)}",
                "system_status": {},
                "tool_status": None
            })

        finally:
            await websocket.close()

    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await websocket.close()

   
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000)