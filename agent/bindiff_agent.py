# VulnAgent/agent/bindiff_agent.py

import os
import json
from datetime import datetime
from uuid import uuid4

from tools.bindiff_tool import run_bindiff
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

    def execute(self, primary_export: str, secondary_export: str) -> dict:
        self.status = TaskStatusEnum.IN_PROGRESS
        self.state["status"] = str(self.status.name)
        self.state["input"] = {
            "primary_export": primary_export,
            "secondary_export": secondary_export,
            "output_dir": self.output_dir
        }
        self._save_state()

        result = run_bindiff(primary_export, secondary_export, self.output_dir)

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
