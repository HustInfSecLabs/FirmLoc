from fastapi import FastAPI, UploadFile, File, Form, status, Request, Query, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import os
import time
import asyncio
import json
from pathlib import Path
from enum import Enum
from datetime import datetime, timezone, timedelta

from agent import VulnAgent
from config import config_manager
from log import logger

app = FastAPI()

app.mount("/static/images", StaticFiles(directory="images"), name="static")

path = config_manager.config["result.path"]["savedir"]

jst = timezone(timedelta(hours=9))

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
    chat_id: int = Form(...)
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
    await websocket.accept()
    last_pong = datetime.now()
    stop_event = asyncio.Event()  # 用于协调协程停止

    async def keep_alive():
        nonlocal last_pong
        while not stop_event.is_set():
            await asyncio.sleep(30)
            if (datetime.now() - last_pong).total_seconds() > 40:
                stop_event.set()
                try:
                    await websocket.close(code=1008)
                except RuntimeError:
                    pass  # 连接可能已关闭
                break
            try:
                await websocket.send_json({"type": "ping"})
            except RuntimeError:
                stop_event.set()
                break

    async def receive_messages():
        nonlocal last_pong
        while not stop_event.is_set():
            try:
                data = await websocket.receive_text()
                message = json.loads(data)

                if message.get("type") == "pong":
                    last_pong = datetime.now()
                    continue

                if not all(key in message for key in ["chat_id", "type", "content"]):
                    try:
                        await websocket.send_json({
                            "error": "Invalid message format",
                            "code": 400
                        })
                    except RuntimeError:
                        stop_event.set()
                    continue

                if message["type"] == "message":
                    VulAgent = VulnAgent(
                        chat_id=message["chat_id"],
                        user_input=message["content"],
                        websocket=websocket,
                    )
                    await VulAgent.chat()

            except json.JSONDecodeError:
                try:
                    await websocket.send_json({"error": "Invalid JSON", "code": 400})
                except RuntimeError:
                    stop_event.set()
            except WebSocketDisconnect:
                stop_event.set()
                break
            except RuntimeError:
                stop_event.set()
                break

    try:
        await asyncio.gather(
            keep_alive(),
            receive_messages()
        )
    except Exception as e:
        print(f"WebSocket error: {str(e)}")
    finally:
        if not stop_event.is_set():
            stop_event.set()
        try:
            await websocket.close()
        except RuntimeError:
            pass  # 连接可能已关闭



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


   
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8888)