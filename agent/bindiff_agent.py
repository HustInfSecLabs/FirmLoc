# VulnAgent/agent/bindiff_agent.py

import os
import json
import random
import asyncio
from datetime import datetime

from utils import ConfigManager
from tools.bindiff_tool import run_bindiff
from tools.bindiff_visual import bindiff_ui
from utils.utils import copy_file, cleanup_dir, rename_file_with_b64_timestamp
from log import logger
from state import ProgressEnum, TaskStatusEnum


class BindiffAgent:
    def __init__(self, chat_id: str, task_name: str = "bindiff_compare"):
        self.chat_id = chat_id
        self.task_name = task_name
        self.agent = "Bindiff Agent"
        self.tool_type = "graphics"
        self.tool_name = "Bindiff"
        self.tool_status = "stop"
        self.status = TaskStatusEnum.NOT_STARTED

        self.output_dir = os.path.join("history", self.chat_id, "bindiff")
        os.makedirs(self.output_dir, exist_ok=True)

        self.state_file = os.path.join(self.output_dir, f"{self.task_name}_state.json")
        self.state = {
            "chat_id": self.chat_id,
            "tool": self.tool_name,
            "task_name": self.task_name,
            "status": str(self.status.name),
            "input": {},
            "result": None,
            "timestamp": str(datetime.now())
        }

    async def execute(self, primary_export: str, secondary_export: str, output_dir: str, config: ConfigManager = None, send_message=None, on_status_update=None) -> dict:
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self.state_file = os.path.join(self.output_dir, f"{self.task_name}_state.json")
        self.status = TaskStatusEnum.IN_PROGRESS
        self.state["status"] = str(self.status.name)
        self.state["input"] = {
            "primary_export": primary_export,
            "secondary_export": secondary_export,
            "output_dir": self.output_dir
        }
        self._save_state()

        result = run_bindiff(primary_export, secondary_export, self.output_dir)
        file1 = os.path.basename(primary_export)
        file2 = os.path.basename(secondary_export)
        src_name = f"{os.path.splitext(file1)[0]}_vs_{os.path.splitext(file2)[0]}.BinDiff"
        # 目标路径为当前目录下的test文件夹
        copy_file(os.path.join(self.output_dir, src_name), os.path.join("test"))
        # bindiff截图
        screenshots = bindiff_ui(os.path.splitext(os.path.basename(primary_export))[0] + f"{str(random.randint(100000, 999999))}", os.path.join(self.output_dir, "images"))
        cleanup_dir(os.path.join("test"))

        links = []
        for screenshot in screenshots:
            file = copy_file(screenshot, "images")
            rename_file = os.path.join("/static", rename_file_with_b64_timestamp(file))
            links.append(rename_file)


        # 更新状态
        config.update_tool_status("IDA Decompiler", "Bindiff")
        if on_status_update:
            on_status_update(None, self.tool_name, self.tool_status)
        tool_content = [
            {
                "type": "text",
                "content": f"Bindiff对比结果已生成: {os.path.basename(primary_export)} vs {os.path.basename(secondary_export)}"
            }
        ] + [
            {"type": "picture", "link": link} for link in links
        ]
        if send_message:
            await send_message(
                f"bindiff {primary_export} {secondary_export} -- output_dir {self.output_dir}",
                "command",
                self.tool_type,
                tool_content,
                agent=self.agent,
                tool=self.tool_name,
                tool_status=self.tool_status
            )
            await asyncio.sleep(1)

        if result.get("success"):
            self.status = TaskStatusEnum.COMPLETED
        else:
            self.status = TaskStatusEnum.FAILED

        self.state["status"] = str(self.status.name)
        self.state["result"] = result
        self._save_state()

        return self.state

    def _save_state(self):
        with open(self.state_file, "w", encoding="utf-8") as f:
            json.dump(self.state, f, indent=4, ensure_ascii=False)
        logger.info(f"[BindiffAgent] 状态已保存: {self.state_file}")
