from fastapi import FastAPI, UploadFile, File, Form, status, Request, Query, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
import os
import time
from pathlib import Path

from agent import VulnAgent
from config import config_manager
from log import logger

VulnAgent = VulnAgent()

app = FastAPI()

path = config_manager.config["result.path"]["savedir"]

# 允许上传的文件类型（二进制或可执行文件）
ALLOWED_CONTENT_TYPES = {
    "application/octet-stream",  # 通用二进制文件类型
    "application/x-msdownload",  # Windows可执行文件 (.exe, .dll)
    "application/x-executable",  # Linux可执行文件
    "application/x-sharedlib",   # Linux共享库 (.so)
    "application/x-mach-binary", # macOS可执行文件
}

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
    if file.content_type not in ALLOWED_CONTENT_TYPES:
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
            "chat_id": chat_id,
            "original_name": file.filename,
            "saved_path": save_path,
            "created_at": int(time.time()),
            "bytes": file_stat.st_size,
        },
    }

@app.get("/v1/system_status")
async def get_system_status(
    chat_id: int = Query(..., description="关联的聊天会话ID", gt=0)
):
    """
    获取智能体系统状态
    
    参数:
    - chat_id: 关联的聊天会话ID
    
    返回:
    - 系统状态信息
    """
    # 检查chat_id是否存在
    if chat_id != VulnAgent.chat_id:
        raise HTTPException(
            status_code=400,
            detail={
                "code": 400,
                "msg": "chat_id不存在",
                "data": None
            }
        )
    
    # 获取系统状态信息
    # session_info = system_sessions[chat_id]
    
    return {
        "code": 0,
        "msg": "查询成功",
        "data": {
            "status": VulnAgent.status,
            "agent": VulnAgent.progress,
            "tool": None
        }
    }

@app.get("/v1/tool_status")
async def get_tool_status(
    chat_id: int = Query(..., description="关联的聊天会话ID", gt=0)
):
    """
    获取智能体工具状态
    
    参数:
    - chat_id: 关联的聊天会话ID
    
    返回:
    - 工具状态信息
    """
    # 检查chat_id是否存在
    if chat_id != VulnAgent.chat_id:
        raise HTTPException(
            status_code=400,
            detail={
                "code": 400,
                "msg": "chat_id不存在",
                "data": None
            }
        )
    
    # 获取工具状态信息
    # session_info = system_sessions[chat_id]
    
    return {
        "code": 0,
        "msg": "查询成功",
        "data": {
            "status": "",
            "agent": "",
            "tool": ""
        }
    }
