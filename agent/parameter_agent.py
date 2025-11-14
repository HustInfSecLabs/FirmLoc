import json
import re
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from agent.base import Agent
from model.base import ChatModel
from log import logger


EXTRACTION_PROMPT = (
    "你是一个专业的安全分析助手，擅长从用户的自然语言需求中提取结构化参数。\n"
    "请从用户输入中提取以下关键字段：\n"
    "- cve_id：形如 CVE-YYYY-NNNN 的编号（区分大小写）。如果没有明确的CVE编号，请返回空字符串。\n"
    "- binary_filename：需要分析的目标固件或二进制文件名称。可以是：\n"
    "  * 完整的文件名（如 firmware.bin、httpd）\n"
    "  * 设备型号（如 Netgear R9000、DIR-878）\n"
    "  * 产品名称（如 DSL-AC3100）\n"
    "  只要用户明确指出要分析的目标，都应提取到此字段。如果完全没有提及任何设备或文件，才返回空字符串。\n\n"
    "严格按照下述 JSON 模板输出（禁止输出额外解释或Markdown标记）：\n"
    "{\n"
    "  \"cve_id\": \"\",          // 字符串，若缺失请保持为空字符串\n"
    "  \"binary_filename\": \"\", // 字符串，若缺失请保持为空字符串\n"
    "  \"confidence\": {\n"
    "    \"cve_id\": \"high|medium|low|none\",\n"
    "    \"binary_filename\": \"high|medium|low|none\"\n"
    "  },\n"
    "  \"notes\": \"\",            // 可选补充说明，可为空字符串\n"
    "  \"missing_fields\": []      // 列表: 例如 [\\\"cve_id\\\"] 表示缺失字段\n"
    "}\n\n"
    "请确保只返回合法的 JSON 文本。用户输入如下：\n"
    "<<<\n"
    "{user_input}\n"
    ">>>\n"
)


class ParameterAgent(Agent):
    """调用大模型抽取漏洞复现所需的关键参数。"""

    REQUIRED_FIELDS = ("cve_id", "binary_filename")

    def __init__(self, chat_model: ChatModel) -> None:
        super().__init__(chat_model)

    def process(self, query: str) -> Dict[str, Any]:  # type: ignore[override]
        """向大模型请求解析结果，并结合启发式兜底逻辑。"""
        query = (query or "").strip()
        logger.info("ParameterAgent processing query: %s", query)
        raw_response: Optional[str] = None
        errors: List[str] = []
        llm_result: Dict[str, Any] = {}

        if not query:
            errors.append("empty_query")
        else:
            prompt = EXTRACTION_PROMPT.replace("{user_input}", query)
            try:
                raw_response = self.chat_model.chat(prompt)
                llm_result = self._parse_response(raw_response)
            except Exception as exc:  # pylint: disable=broad-except
                logger.error("ParameterAgent LLM call failed: %s", exc)
                errors.append(str(exc))
                llm_result = {}

        normalized = self._normalize_result(llm_result)
        heuristic = self._heuristic_extract(query)

        for field in self.REQUIRED_FIELDS:
            if not normalized.get(field) and heuristic.get(field):
                normalized[field] = heuristic[field]

        missing = [field for field in self.REQUIRED_FIELDS if not normalized.get(field)]
        normalized["missing_fields"] = missing
        if errors:
            normalized.setdefault("errors", []).extend(errors)
        if raw_response is not None:
            normalized.setdefault("raw_response", raw_response)

        logger.info("ParameterAgent result: %s", normalized)
        return normalized

    def _parse_response(self, response: str) -> Dict[str, Any]:
        if not response:
            raise ValueError("empty response from LLM")

        response = response.strip()
        # 直接尝试解析完整 JSON
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass

        # 提取 ```json ``` 代码块
        fenced_match = re.search(r"```json\s*([\s\S]+?)```", response, re.IGNORECASE)
        if fenced_match:
            fenced_content = fenced_match.group(1).strip()
            try:
                return json.loads(fenced_content)
            except json.JSONDecodeError as exc:  # pylint: disable=broad-except
                logger.warning("Failed to parse fenced JSON: %s", exc)

        # 提取第一个大括号包裹的 JSON 片段
        brace_match = self._extract_brace_block(response)
        if brace_match:
            try:
                return json.loads(brace_match)
            except json.JSONDecodeError as exc:
                logger.warning("Failed to parse brace JSON: %s", exc)

        raise ValueError("LLM response is not valid JSON")

    def _extract_brace_block(self, text: str) -> Optional[str]:
        stack: List[int] = []
        start = None
        for index, char in enumerate(text):
            if char == '{':
                stack.append(index)
                if start is None:
                    start = index
            elif char == '}':
                if stack:
                    stack.pop()
                    if not stack and start is not None:
                        return text[start:index + 1]
        return None

    def _normalize_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        normalized = {
            "cve_id": (result or {}).get("cve_id", "").strip() if result else "",
            "binary_filename": (result or {}).get("binary_filename", "").strip() if result else "",
            "confidence": (result or {}).get("confidence", {}),
            "notes": (result or {}).get("notes", ""),
            "missing_fields": (result or {}).get("missing_fields", []),
        }
        return normalized

    def _heuristic_extract(self, query: str) -> Dict[str, Optional[str]]:
        if not query:
            return {"cve_id": None, "binary_filename": None}

        cve_match = re.search(r"CVE-\d{4}-\d{4,7}", query, re.IGNORECASE)
        cve_id = cve_match.group(0).upper() if cve_match else None

        binary_name = None
        heuristics: List[Tuple[str, str]] = [
            (r"binary\s*(?:name|filename|file)?\s*(?:is|=|:)?\s*([\w .\-]+)", "binary keyword"),
            (r"(?:固件|文件|二进制)名(?:称)?(?:是|为|:|：)\s*([\w .\-]+)", "zh filename is"),
            (r"目标(?:固件|二进制)[^\w]*([\w .\-]{3,})", "zh target"),
            (r"设备名称[:：]\s*([\w .\-]+)", "device name"),
            (r"分析\s*([\w .\-]+)\s*(?:固件|设备|路由器)", "zh analyze device"),
        ]

        for pattern, source in heuristics:
            match = re.search(pattern, query, re.IGNORECASE)
            if match:
                candidate = match.group(1).strip().strip('"')
                if candidate:
                    binary_name = candidate
                    logger.debug("Heuristic binary name match (%s): %s", source, candidate)
                    break

        return {"cve_id": cve_id, "binary_filename": binary_name}


class ParameterCollector:
    """在系统运行前与用户交互，收集必要的参数。"""

    FIELD_PROMPTS = {
        "cve_id": "未识别到明确的 CVE ID。请提供形如 CVE-2024-12345 的编号，便于后续检索。",
        "binary_filename": "未识别到目标固件/二进制名称。请说明需要分析的设备或二进制文件名称。",
    }

    def __init__(
        self,
        chat_id: str,
        send_callback: Callable[[Dict[str, Any]], Awaitable[None]],
        chat_model: ChatModel,
        parameter_agent: Optional[ParameterAgent] = None
    ) -> None:
        self.chat_id = str(chat_id)
        self.agent = parameter_agent or ParameterAgent(chat_model)
        self._send_callback = send_callback
        self.parameters: Dict[str, Optional[str]] = {field: None for field in ParameterAgent.REQUIRED_FIELDS}
        self.prompted_fields: set[str] = set()
        self.initial_message_sent = False
        self.completed = False
        self.history: List[str] = []
        self.original_query: Optional[str] = None

    def update_sender(self, send_callback: Callable[[Dict[str, Any]], Awaitable[None]]) -> None:
        self._send_callback = send_callback

    async def handle_message(self, message: str) -> Dict[str, Any]:
        message = (message or "").strip()
        if message:
            self.history.append(message)
            if self.original_query is None:
                self.original_query = message
        if not self.initial_message_sent:
            await self._send("参数收集智能体已启动，正在解析您的需求。", message_type="header1")
            self.initial_message_sent = True

        result = self.agent.process(message)
        for field in ParameterAgent.REQUIRED_FIELDS:
            value = result.get(field)
            if isinstance(value, str) and value.strip():
                self.parameters[field] = value.strip()

        missing = [field for field in ParameterAgent.REQUIRED_FIELDS if not self.parameters.get(field)]

        if result.get("errors"):
            await self._send("参数解析时出现异常，已启用兜底策略，请确认后继续。")

        if missing:
            prompts = []
            for field in missing:
                if field not in self.prompted_fields:
                    prompts.append(self.FIELD_PROMPTS.get(field, f"请提供 {field}"))
                    self.prompted_fields.add(field)
            if prompts:
                await self._send("\n".join(prompts))
            else:
                await self._send("仍然缺少必要信息，请补充上述参数后再次发送。")
            return {
                "ready": False,
                "parameters": self.parameters.copy(),
                "missing": missing,
                "query": "\n".join(self.history)
            }

        if not self.completed:
            summary = (
                "参数收集完成。\n"
                f"- CVE ID: {self.parameters['cve_id']}\n"
                f"- 目标二进制/固件: {self.parameters['binary_filename']}\n"
                "系统将继续执行后续分析。"
            )
            await self._send(summary, message_type="header2")
            self.completed = True

        return {
            "ready": True,
            "parameters": self.parameters.copy(),
            "missing": [],
            "query": "\n".join(self.history)
        }

    async def _send(self, content: str, message_type: str = "message") -> None:
        payload = {
            "chat_id": self.chat_id,
            "is_last": False,
            "type": message_type,
            "content": content,
            "system_status": {
                "status": "PARAMETER_AGENT",
                "agent": "Parameter Agent",
                "tool": None
            },
            "tool_status": None
        }
        try:
            await self._send_callback(payload)
            logger.info("ParameterCollector sent message: %s", payload)
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Failed to send parameter message: %s", exc)