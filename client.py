import websockets
import asyncio
import json
import os
import requests
import random

# ========== 配置项 ==========
# 本地固件文件路径，修改为你自己的路径
FIRMWARE_PATH1 = "/home/wzh/Desktop/DSL-AC3100_v1.10.06_build591.w"
FIRMWARE_PATH2 = "/home/wzh/Desktop/DSL-AC3100_v1.10.08_build593.w"
# 对应的 chat_id 随机生成
CHAT_ID = random.randint(100000, 999999)
# 上传接口地址（根据你的服务地址修改）
UPLOAD_URL = "http://localhost:8000/v1/files"

async def test_client(chat_id: int = CHAT_ID):
    uri = "ws://localhost:8000/v1/chat"
    async with websockets.connect(uri) as websocket:
        # 发送请求
        await websocket.send(json.dumps({
            "chat_id": chat_id,
            "type": "message",
            "content": "请根据两个版本的固件文件，分析它们的差异，并给出可能存在的漏洞和成因。",
        }))
        
        # 接收响应
        while True:
            print("Waiting for response...")
            try:
                response = await websocket.recv()
                print("Received:", json.loads(response))
            except websockets.exceptions.ConnectionClosed:
                print("Connection closed")
                break

def upload_firmware(firmware_path: str, chat_id: int):
    if not os.path.isfile(firmware_path):
        print(f"[错误] 固件文件不存在：{firmware_path}")
        return

    filename = os.path.basename(firmware_path)
    # 根据后缀简易判断 Content-Type，可按需扩展
    content_type = "application/octet-stream"

    with open(firmware_path, "rb") as f:
        files = {
            "file": (filename, f, content_type)
        }
        data = {
            "chat_id": str(chat_id)
        }
        print(f"正在上传 {filename} 到 chat_id={chat_id} …")
        resp = requests.post(UPLOAD_URL, files=files, data=data)

    try:
        resp_json = resp.json()
    except ValueError:
        print(f"[错误] 返回非 JSON 响应，HTTP 状态码：{resp.status_code}")
        return

    if resp.status_code == 200 and resp_json.get("code") == 0:
        print("上传成功！返回数据：")
        print(resp_json["data"])
    else:
        print(f"[失败] 状态码：{resp.status_code}，消息：{resp_json.get('msg')}")            


upload_firmware(FIRMWARE_PATH1, CHAT_ID)
upload_firmware(FIRMWARE_PATH2, CHAT_ID)
asyncio.get_event_loop().run_until_complete(test_client(CHAT_ID))