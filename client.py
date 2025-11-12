import asyncio
import json
import os
import random
from typing import Any, Dict, Optional

import requests
import websockets
from websockets.exceptions import ConnectionClosed


# ========== 配置项 ==========
API_HOST = os.getenv("API_HOST", "localhost:8000")
UPLOAD_URL = f"http://{API_HOST}/v1/files"
CHAT_WS_URL = f"ws://{API_HOST}/v1/chat"

DEFAULT_INITIAL_PROMPT = os.getenv(
    "INITIAL_PROMPT",
    "请根据两个版本的固件文件，分析它们的差异，并给出可能存在的漏洞和成因。",
)

FIRMWARE_PATHS = [
    os.getenv("FIRMWARE_PATH1", "/home/wzh/Desktop/DSL-AC3100_v1.10.06_build591.w"),
    os.getenv("FIRMWARE_PATH2", "/home/wzh/Desktop/DSL-AC3100_v1.10.08_build593.w"),
]

CHAT_ID = str(os.getenv("CHAT_ID") or random.randint(100000, 999999))


def upload_firmware(firmware_path: Optional[str], chat_id: str) -> None:
    if not firmware_path:
        return
    if not os.path.isfile(firmware_path):
        print(f"[警告] 固件文件不存在：{firmware_path}")
        return

    filename = os.path.basename(firmware_path)
    content_type = "application/octet-stream"
    print(f"正在上传 {filename} 到 chat_id={chat_id} …")

    try:
        with open(firmware_path, "rb") as file_handle:
            files = {"file": (filename, file_handle, content_type)}
            data = {"chat_id": chat_id}
            response = requests.post(UPLOAD_URL, files=files, data=data, timeout=30)
    except requests.RequestException as exc:
        print(f"[失败] 上传请求异常：{exc}")
        return

    try:
        payload = response.json()
    except ValueError:
        print(f"[失败] 返回非 JSON 响应，HTTP 状态码：{response.status_code}")
        return

    if response.status_code == 200 and payload.get("code") == 0:
        print("上传成功：", payload.get("data"))
    else:
        print(f"[失败] 状态码：{response.status_code}，消息：{payload.get('msg')}")


async def send_chat_message(websocket: websockets.WebSocketClientProtocol, chat_id: str, content: str) -> None:
    message = {
        "chat_id": chat_id,
        "type": "message",
        "content": content,
    }
    await websocket.send(json.dumps(message, ensure_ascii=False))
    print(f"[-> MESSAGE] {content}")


def pretty_print_message(message: Dict[str, Any]) -> None:
    msg_type = message.get("type", "message")
    prefix = f"[<- {msg_type.upper()}]"
    content = message.get("content")

    if isinstance(content, str) and content:
        print(f"{prefix} {content}")
    else:
        print(prefix, json.dumps(message, ensure_ascii=False, indent=2))

    system_status = message.get("system_status")
    if system_status:
        print("    system_status:", system_status)

    tool_status = message.get("tool_status")
    if tool_status:
        print("    tool_status:", tool_status)


async def handle_incoming_messages(
    websocket: websockets.WebSocketClientProtocol,
    chat_id: str,
    stop_event: asyncio.Event,
) -> None:
    while not stop_event.is_set():
        try:
            raw = await websocket.recv()
        except ConnectionClosed:
            print("[info] WebSocket 连接已关闭。")
            stop_event.set()
            break
        except Exception as exc:  # pylint: disable=broad-except
            print(f"[错误] 接收消息时发生异常：{exc}")
            stop_event.set()
            break

        try:
            message = json.loads(raw)
        except json.JSONDecodeError:
            print("[警告] 收到非 JSON 消息：", raw)
            continue

        msg_type = message.get("type")

        if msg_type == "ping":
            await websocket.send(json.dumps({"type": "pong"}))
            continue

        pretty_print_message(message)

        if msg_type == "close":
            stop_event.set()
            break


async def interactive_input_loop(
    websocket: websockets.WebSocketClientProtocol,
    chat_id: str,
    stop_event: asyncio.Event,
) -> None:
    loop = asyncio.get_running_loop()

    while not stop_event.is_set():
        user_text = await loop.run_in_executor(None, lambda: input("[你] ").strip())
        if stop_event.is_set():
            break
        if not user_text:
            continue

        if user_text.lower() in {"exit", "quit", "\u9000\u51fa"}:  # 支持 exit/quit/退出
            print("[info] 即将关闭会话…")
            stop_event.set()
            await websocket.close()
            break

        await send_chat_message(websocket, chat_id, user_text)


async def chat_session(chat_id: str, initial_prompt: str) -> None:
    print(f"[info] 即将发起 WebSocket 会话：chat_id={chat_id}")
    stop_event = asyncio.Event()

    try:
        async with websockets.connect(CHAT_WS_URL, ping_interval=None) as websocket:
            print("[info] WebSocket 已连接。")
            await send_chat_message(websocket, chat_id, initial_prompt)

            listener_task = asyncio.create_task(handle_incoming_messages(websocket, chat_id, stop_event))
            input_task = asyncio.create_task(interactive_input_loop(websocket, chat_id, stop_event))

            try:
                await stop_event.wait()
            finally:
                listener_task.cancel()
                input_task.cancel()
                await asyncio.gather(listener_task, input_task, return_exceptions=True)

    except OSError as exc:
        print(f"[错误] 无法连接到 WebSocket：{exc}")


async def main() -> None:
    print("========== VulnAgent 客户端 ==========")
    print(f"API 地址: {API_HOST}")
    chat_id = CHAT_ID
    print(f"chat_id: {chat_id}")

    for firmware_path in FIRMWARE_PATHS:
        upload_firmware(firmware_path, chat_id)

    await chat_session(chat_id, DEFAULT_INITIAL_PROMPT)


if __name__ == "__main__":
    asyncio.run(main())