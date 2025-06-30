from fastapi import FastAPI, UploadFile, File, Form, status, Request, Query, HTTPException, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import os
import time
import asyncio
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from enum import Enum
from datetime import datetime, timezone, timedelta

from agent import VulnAgent, run_repair_agent
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
    await websocket.accept()
    last_pong = datetime.now()
    stop_event = asyncio.Event()
    worker_finished = asyncio.Event()
    # 创建专用的线程池执行器
    executor = ThreadPoolExecutor(max_workers=1)

    async def keep_alive():
        nonlocal last_pong
        while not stop_event.is_set():
            await asyncio.sleep(10)  # 每10秒发送一次pong
            if (datetime.now() - last_pong).total_seconds() > 1200:
                logger.warning("No pong received in 20 minutes, closing WebSocket.")
                stop_event.set()
                try:
                    await websocket.close(code=1008)
                except RuntimeError:
                    pass
                break
            
            try:
                if websocket.client_state == WebSocketState.CONNECTED:
                    await websocket.send_json({"type": "pong"})
                    logger.info("Keep-alive pong sent.")
                else:
                    logger.warning("WebSocket is already closed. Stopping keep_alive.")
                    stop_event.set()
                    break
            except Exception as e:
                logger.error(f"Keep-alive pong failed: {str(e)}")
                stop_event.set()
                break

    async def receive_messages():
        nonlocal last_pong
        while not stop_event.is_set():
            try:
                # 检查 worker 是否完成
                if worker_finished.is_set():
                    logger.info("Worker finished, closing WebSocket")
                    stop_event.set()
                    break

                data = await asyncio.wait_for(websocket.receive_text(), timeout=0.1)
                message = json.loads(data)
                logger.info(f"Received message: {message}")
                
                # 处理 ping/pong 消息
                if message.get("type") in ["pong", "ping"]:
                    last_pong = datetime.now()
                    logger.info(f"Received {message['type']} message.")
                    continue

                # 校验消息格式
                if not all(key in message for key in ["chat_id", "type", "content"]):
                    await websocket.send_json({
                        "error": "Invalid message format",
                        "code": 400
                    })
                    continue

                # 根据消息类型处理
                if message["type"] == "message":
                    # 在独立线程中运行 VulnAgent
                    def run_agent():
                        try:
                            # 创建新的事件循环给VulnAgent使用
                            new_loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(new_loop)
                            
                            agent = VulnAgent(message["chat_id"], message["content"], websocket)
                            
                            # 在新事件循环中运行chat
                            new_loop.run_until_complete(agent.chat())
                            logger.info("VulnAgent.chat completed successfully")
                        except Exception as e:
                            logger.error("VulnAgent.chat 线程内错误: %s", e)
                        finally:
                            # 关闭新事件循环
                            new_loop.close()
                            # 通知主协程worker已完成
                            main_loop = asyncio.get_event_loop()
                            main_loop.call_soon_threadsafe(worker_finished.set)

                    # 使用线程池执行
                    await asyncio.get_event_loop().run_in_executor(executor, run_agent)
                    
                else:
                    await websocket.send_json({
                        "error": f"Unsupported message type: {message['type']}",
                        "code": 400
                    })

            except asyncio.TimeoutError:
                continue  # 继续循环检查 worker_finished
            except json.JSONDecodeError:
                await websocket.send_json({"error": "Invalid JSON", "code": 400})
            except WebSocketDisconnect:
                logger.info("WebSocket disconnected.")
                stop_event.set()
                break
            except Exception as e:
                logger.error(f"Error in receive_messages: {str(e)}")
                stop_event.set()
                break

    try:
        # 并发运行keep_alive和receive_messages
        await asyncio.gather(
            keep_alive(),
            receive_messages(),
            return_exceptions=True
        )
    except Exception as e:
        logger.error(f"WebSocket error: {str(e)}")
    finally:
        if not stop_event.is_set():
            stop_event.set()
        
        # 关闭线程池
        executor.shutdown(wait=False)
        
        try:
            if websocket.client_state == WebSocketState.CONNECTED:
                logger.info("Closing WebSocket connection.")
                await websocket.send_json({"type": "close", "message": "Chat completed"})
                await asyncio.sleep(1)
                await websocket.close()
        except RuntimeError:
            logger.warning("WebSocket already closed.")
            pass



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
async def code_repair_ws(websocket: WebSocket, chat_id: str = Query(...)):
    await websocket.accept()
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

   
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000)