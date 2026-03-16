import json
import os
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set

from agent.base import Agent
from log import logger
from model.base import ChatModel


jst = timezone(timedelta(hours=9))

SOURCE_DIFF_EXTRACTION_PROMPT = (
    "你是一个专业的安全分析助手，擅长从用户的多轮对话中提取源码比对参数。\n"
    "当前 Source Diff 工作区中有以下文件：\n"
    "{file_list}\n\n"
    "历史已收集参数如下：\n"
    "{existing_params}\n\n"
    "请从用户输入中提取以下字段：\n"
    "- file1：变更前文件名，必须来自文件列表\n"
    "- file2：变更后文件名，必须来自文件列表\n"
    "- cve_id：若用户提供了 CVE-YYYY-NNNN，则提取，否则为空字符串\n"
    "- cwe：若用户提供了 CWE 编号，则提取，否则为空字符串\n"
    "- cve_details：若用户给出了漏洞背景、补丁说明或 CVE 描述，则提取，否则为空字符串\n\n"
    "要求：\n"
    "1. 保留历史已收集参数，除非用户明确修改\n"
    "2. file1/file2 必须与文件列表匹配\n"
    "3. 只输出 JSON，不要输出额外解释\n\n"
    "JSON 模板如下：\n"
    "{\n"
    "  \"file1\": \"\",\n"
    "  \"file2\": \"\",\n"
    "  \"cve_id\": \"\",\n"
    "  \"cwe\": \"\",\n"
    "  \"cve_details\": \"\",\n"
    "  \"missing_fields\": []\n"
    "}\n\n"
    "完整历史对话如下：\n"
    "<<<\n"
    "{user_input}\n"
    ">>>\n"
)


class SourceDiffParameterAgent(Agent):
    REQUIRED_FIELDS = ("file1", "file2")

    def __init__(self, chat_model: ChatModel) -> None:
        super().__init__(chat_model)

    def process(
        self,
        query: str,
        file_list: List[str],
        existing_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        query = (query or "").strip()
        existing_params = existing_params or {}
        logger.info("SourceDiffParameterAgent processing query: %s", query)

        if not file_list:
            return {
                "file1": "",
                "file2": "",
                "cve_id": "",
                "cwe": "",
                "cve_details": "",
                "missing_fields": list(self.REQUIRED_FIELDS),
            }

        prompt = SOURCE_DIFF_EXTRACTION_PROMPT.format(
            user_input=query,
            file_list="\n".join(f"- {name}" for name in file_list),
            existing_params=self._format_existing_params(existing_params),
        )

        try:
            raw_response = self.chat_model.chat(prompt)
            result = self._parse_response(raw_response)
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("SourceDiffParameterAgent LLM call failed: %s", exc)
            result = {}

        normalized = self._normalize_result(result, file_list, existing_params)
        normalized["missing_fields"] = [
            field for field in self.REQUIRED_FIELDS if not normalized.get(field)
        ]
        logger.info("SourceDiffParameterAgent result: %s", normalized)
        return normalized

    def _format_existing_params(self, existing_params: Dict[str, Any]) -> str:
        lines = []
        for key in ["file1", "file2", "cve_id", "cwe", "cve_details"]:
            value = existing_params.get(key)
            if isinstance(value, str) and value.strip():
                lines.append(f"- {key}: {value.strip()}")
        return "\n".join(lines) if lines else "（暂无）"

    def _parse_response(self, response: str) -> Dict[str, Any]:
        if not response:
            raise ValueError("empty response from LLM")

        response = response.strip()
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass

        fenced_match = re.search(r"```json\s*([\s\S]+?)```", response, re.IGNORECASE)
        if fenced_match:
            return json.loads(fenced_match.group(1).strip())

        start = response.find("{")
        end = response.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(response[start : end + 1])

        raise ValueError("LLM response is not valid JSON")

    def _normalize_result(
        self,
        result: Dict[str, Any],
        file_list: List[str],
        existing_params: Dict[str, Any],
    ) -> Dict[str, Any]:
        normalized = {
            "file1": self._validate_filename((result or {}).get("file1", ""), file_list),
            "file2": self._validate_filename((result or {}).get("file2", ""), file_list),
            "cve_id": self._clean_text((result or {}).get("cve_id", "")),
            "cwe": self._clean_text((result or {}).get("cwe", "")),
            "cve_details": self._clean_text((result or {}).get("cve_details", "")),
        }

        for field in ["file1", "file2", "cve_id", "cwe", "cve_details"]:
            if not normalized.get(field):
                existing_value = existing_params.get(field)
                if isinstance(existing_value, str) and existing_value.strip():
                    normalized[field] = existing_value.strip()

        return normalized

    def _clean_text(self, value: Any) -> str:
        if not isinstance(value, str):
            return ""
        return value.strip().strip('"').strip("'")

    def _validate_filename(self, filename: Any, file_list: List[str]) -> str:
        if not isinstance(filename, str):
            return ""

        clean_name = Path(filename.strip().strip('"').strip("'")).name
        if not clean_name:
            return ""

        if clean_name in file_list:
            return clean_name

        for candidate in file_list:
            if candidate.lower() == clean_name.lower():
                return candidate

        contains_matches = [candidate for candidate in file_list if clean_name.lower() in candidate.lower()]
        if len(contains_matches) == 1:
            return contains_matches[0]

        stem_matches = [candidate for candidate in file_list if Path(candidate).stem.lower() == Path(clean_name).stem.lower()]
        if len(stem_matches) == 1:
            return stem_matches[0]

        return ""


class SourceDiffParameterCollector:
    FIELD_PROMPTS = {
        "file1": "请指定第一个源码文件（变更前）。",
        "file2": "请指定第二个源码文件（变更后）。",
    }

    def __init__(
        self,
        chat_id: str,
        base_dir: str,
        send_callback: Callable[[Dict[str, Any]], Awaitable[None]],
        chat_model: ChatModel,
        allowed_extensions: Optional[Set[str]] = None,
    ) -> None:
        self.chat_id = str(chat_id)
        self.base_dir = base_dir
        self._send_callback = send_callback
        self.agent = SourceDiffParameterAgent(chat_model)
        self.allowed_extensions = {ext.lower() for ext in (allowed_extensions or set())}
        self.parameters: Dict[str, Optional[str]] = {
            "file1": None,
            "file2": None,
            "cve_id": None,
            "cwe": None,
            "cve_details": None,
        }
        self.history: List[str] = []
        self.prompted_fields: Set[str] = set()
        self.initial_message_sent = False
        self.completed = False

    def update_sender(self, send_callback: Callable[[Dict[str, Any]], Awaitable[None]]) -> None:
        self._send_callback = send_callback

    def _get_file_list(self) -> List[str]:
        if not os.path.exists(self.base_dir):
            return []

        result: List[str] = []
        for filename in sorted(os.listdir(self.base_dir)):
            file_path = os.path.join(self.base_dir, filename)
            if not os.path.isfile(file_path):
                continue
            ext = Path(filename).suffix.lower()
            if self.allowed_extensions and ext not in self.allowed_extensions:
                continue
            result.append(filename)
        return result

    async def handle_message(self, message: str) -> Dict[str, Any]:
        message = (message or "").strip()
        if message:
            self.history.append(message)

        file_list = self._get_file_list()
        if not self.initial_message_sent:
            files_msg = "\n".join(f"- {name}" for name in file_list) if file_list else "当前暂无源码文件，请先上传。"
            await self._send(
                "Source Diff 助手已启动。\n"
                f"当前可用源码文件：\n{files_msg}\n"
                "请告诉我要比对的 file1 和 file2。",
                message_type="header1",
                status="running",
                phase="parameter_collection",
            )
            self.initial_message_sent = True

        if not file_list:
            await self._send(
                "当前会话下还没有可用源码文件，请先通过 /v1/sourceDiff/files 上传源码文件。",
                status="failed",
                phase="parameter_collection",
            )
            return {"ready": False, "missing": list(SourceDiffParameterAgent.REQUIRED_FIELDS)}

        query_context = "\n".join(self.history)
        result = self.agent.process(query_context, file_list, self.parameters)

        for field in ["file1", "file2", "cve_id", "cwe", "cve_details"]:
            value = result.get(field)
            if isinstance(value, str) and value.strip():
                self.parameters[field] = value.strip()

        missing = [field for field in SourceDiffParameterAgent.REQUIRED_FIELDS if not self.parameters.get(field)]
        if missing:
            prompts = []
            for field in missing:
                if field not in self.prompted_fields:
                    prompts.append(self.FIELD_PROMPTS.get(field, f"请提供 {field}"))
                    self.prompted_fields.add(field)

            if not prompts:
                prompts.append("请直接给出要比对的两个文件名，例如：file1=a.c, file2=b.c")

            await self._send(
                "\n".join(prompts),
                status="running",
                phase="parameter_collection",
            )
            return {
                "ready": False,
                "parameters": self.parameters.copy(),
                "missing": missing,
            }

        if not self.completed:
            await self._send(
                "参数收集完成，准备开始源码 diff 分析。\n"
                f"- file1: {self.parameters['file1']}\n"
                f"- file2: {self.parameters['file2']}\n"
                f"- cve_id: {self.parameters['cve_id'] or 'N/A'}\n"
                f"- cwe: {self.parameters['cwe'] or 'N/A'}",
                message_type="header2",
                status="running",
                phase="parameter_collection",
            )
            self.completed = True

        return {
            "ready": True,
            "parameters": self.parameters.copy(),
            "missing": [],
        }

    async def _send(
        self,
        content: str,
        message_type: str = "message",
        status: str = "running",
        phase: str = "parameter_collection",
    ) -> None:
        payload = {
            "chat_id": self.chat_id,
            "is_last": False,
            "type": message_type,
            "content": content,
            "system_status": {
                "status": status,
                "agent": "Source Diff Parameter Agent",
                "tool": None,
                "phase": phase,
            },
            "tool_status": None,
            "timestamp": datetime.now(tz=jst).isoformat(),
        }
        try:
            await self._send_callback(payload)
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Failed to send Source Diff parameter message: %s", exc)
