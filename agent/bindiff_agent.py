# VulnAgent/agent/bindiff_agent.py

import os
import json
from datetime import datetime

from tools.bindiff_tool import run_bindiff
from tools.bindiff_visual import bindiff_ui
from utils.utils import copy_file, cleanup_dir
from log import logger
from state import ProgressEnum, TaskStatusEnum


class BindiffAgent:
    def __init__(self, chat_id: str, task_name: str = "bindiff_compare"):
        self.chat_id = chat_id
        self.task_name = task_name
        self.tool_name = "bindiff"
        self.status = TaskStatusEnum.NOT_STARTED

        self.output_dir = os.path.join("history", self.chat_id, self.tool_name)
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

    def execute(self, primary_export: str, secondary_export: str, output_dir: str) -> dict:
        self.output_dir = output_dir
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
        # bindiff_ui(os.path.basename(primary_export), os.path.join(self.output_dir, "images"))
        cleanup_dir(os.path.join("test"))

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
