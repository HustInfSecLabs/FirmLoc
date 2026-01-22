import json
import re
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from agent.base import Agent
from model.base import ChatModel
from log import logger


class WorkMode(str, Enum):
    """工作模式枚举"""
    REPRODUCTION = "reproduction"  # 漏洞复现模式（需要CVE ID）
    DISCOVERY = "discovery"        # 漏洞挖掘模式（需要CWE类型）


# CWE类型到敏感二进制的映射，用于漏洞挖掘模式下的启发式筛选
CWE_SENSITIVE_BINARIES = {
    "CWE-78": ["httpd", "cgi", "mini_httpd", "goahead", "boa", "uhttpd", "lighttpd", "busybox", "sh", "ash", "system"],
    "CWE-77": ["httpd", "cgi", "mini_httpd", "goahead", "boa", "uhttpd", "lighttpd", "busybox", "sh", "ash"],
    "CWE-120": ["httpd", "upnpd", "samba", "ftpd", "telnetd", "sshd", "dhcpd", "dnsd"],
    "CWE-121": ["httpd", "upnpd", "samba", "ftpd", "telnetd", "sshd", "dhcpd", "dnsd"],
    "CWE-122": ["httpd", "upnpd", "samba", "ftpd", "telnetd", "sshd", "dhcpd", "dnsd"],
    "CWE-125": ["httpd", "upnpd", "samba", "parser", "decoder"],
    "CWE-787": ["httpd", "upnpd", "samba", "ftpd", "telnetd", "sshd", "parser"],
    "CWE-22": ["httpd", "ftpd", "samba", "mini_httpd", "goahead", "boa", "uhttpd", "file"],
    "CWE-23": ["httpd", "ftpd", "samba", "mini_httpd", "goahead", "boa", "uhttpd", "file"],
    "CWE-416": ["httpd", "upnpd", "samba", "malloc", "free"],
    "CWE-415": ["httpd", "upnpd", "samba", "malloc", "free"],
    "CWE-476": ["httpd", "upnpd", "samba", "parser"],
    "CWE-134": ["httpd", "cgi", "syslog", "printf", "format"],
    "CWE-190": ["httpd", "parser", "decoder", "atoi", "strtol"],
    "CWE-191": ["httpd", "parser", "decoder", "atoi", "strtol"],
    "CWE-798": ["httpd", "login", "auth", "password", "admin", "config"],
    "CWE-259": ["httpd", "login", "auth", "password", "admin", "config"],
    "CWE-287": ["httpd", "login", "auth", "session", "token", "cookie"],
    "CWE-306": ["httpd", "cgi", "api", "admin"],
    "CWE-352": ["httpd", "cgi", "web", "form"],
    "CWE-434": ["httpd", "upload", "cgi", "file"],
    "CWE-502": ["httpd", "deserialize", "json", "xml", "pickle"],
    "CWE-611": ["xml", "parser", "libxml", "expat"],
    "CWE-918": ["httpd", "curl", "wget", "http", "request"],
}

# CWE类型描述映射
CWE_DESCRIPTIONS = {
    "CWE-78": "OS Command Injection - 操作系统命令注入漏洞",
    "CWE-77": "Command Injection - 命令注入漏洞",
    "CWE-120": "Buffer Copy without Checking Size of Input - 缓冲区溢出漏洞",
    "CWE-121": "Stack-based Buffer Overflow - 栈缓冲区溢出漏洞",
    "CWE-122": "Heap-based Buffer Overflow - 堆缓冲区溢出漏洞",
    "CWE-125": "Out-of-bounds Read - 越界读取漏洞",
    "CWE-787": "Out-of-bounds Write - 越界写入漏洞",
    "CWE-22": "Path Traversal - 路径遍历漏洞",
    "CWE-23": "Relative Path Traversal - 相对路径遍历漏洞",
    "CWE-416": "Use After Free - 释放后使用漏洞",
    "CWE-415": "Double Free - 双重释放漏洞",
    "CWE-476": "NULL Pointer Dereference - 空指针解引用漏洞",
    "CWE-134": "Use of Externally-Controlled Format String - 格式化字符串漏洞",
    "CWE-190": "Integer Overflow - 整数溢出漏洞",
    "CWE-191": "Integer Underflow - 整数下溢漏洞",
    "CWE-798": "Use of Hard-coded Credentials - 硬编码凭证漏洞",
    "CWE-259": "Use of Hard-coded Password - 硬编码密码漏洞",
    "CWE-287": "Improper Authentication - 不当认证漏洞",
    "CWE-306": "Missing Authentication for Critical Function - 关键功能缺少认证",
    "CWE-352": "Cross-Site Request Forgery - CSRF漏洞",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type - 危险文件上传漏洞",
    "CWE-502": "Deserialization of Untrusted Data - 不可信数据反序列化漏洞",
    "CWE-611": "XML External Entity Reference - XXE漏洞",
    "CWE-918": "Server-Side Request Forgery - SSRF漏洞",
}


EXTRACTION_PROMPT_DISCOVERY = (
    "你是一个专业的安全分析助手，擅长从用户的多轮对话中提取和维护结构化参数。\n"
    "当前为【漏洞挖掘模式】，用户希望基于CWE漏洞类型在固件中发现潜在漏洞。\n\n"
    "需要提取的关键字段（必填）：\n"
    "1. cwe_id：形如 CWE-XXX 的漏洞类型编号（如 CWE-78、CWE-120）\n"
    "   支持从漏洞类型描述中推断：\n"
    "   * '命令注入' -> CWE-78\n"
    "   * '缓冲区溢出' -> CWE-120\n"
    "   * '栈溢出' -> CWE-121\n"
    "   * '堆溢出' -> CWE-122\n"
    "   * '路径遍历' -> CWE-22\n"
    "   * '格式化字符串' -> CWE-134\n"
    "   * '整数溢出' -> CWE-190\n"
    "   * '越界写入' -> CWE-787\n"
    "   * '越界读取' -> CWE-125\n"
    "   * 'UAF/释放后使用' -> CWE-416\n\n"
    "2. binary_filename：目标固件或二进制文件名称\n"
    "   可以是文件名（如 httpd、firmware.bin）、设备型号（如 DIR-878）、\n"
    "   产品名称（如 DSL-AC3100）、厂商名称（如 QNAP）等任何能定位目标的信息\n\n"
    "可选字段：\n"
    "- vendor：设备厂商名称（如 Netgear、D-Link、TP-Link、ASUS、Tenda、QNAP等）\n"
    "- cve_id：如果用户提供了参考CVE编号（形如 CVE-YYYY-NNNN）\n\n"
    "【历史已收集的参数】：\n"
    "{existing_params}\n\n"
    "【重要】：\n"
    "1. 请保留历史已收集的参数，除非本次用户明确要修改\n"
    "2. 新的用户输入可能只是补充缺失的信息，不要覆盖已有信息\n"
    "3. 仔细分析所有历史对话，综合提取完整参数\n\n"
    "严格按照下述 JSON 模板输出（禁止输出额外解释或Markdown标记）：\n"
    "{\n"
    "  \"cwe_id\": \"\",           // 字符串，若仍未找到保持为空\n"
    "  \"cve_id\": \"\",           // 字符串（可选），若未提及保持为空\n"
    "  \"binary_filename\": \"\",  // 字符串，若仍未找到保持为空\n"
    "  \"vendor\": \"\",           // 字符串（可选），若未提及保持为空\n"
    "  \"confidence\": {\n"
    "    \"cwe_id\": \"high|medium|low|none\",\n"
    "    \"cve_id\": \"high|medium|low|none\",\n"
    "    \"binary_filename\": \"high|medium|low|none\",\n"
    "    \"vendor\": \"high|medium|low|none\"\n"
    "  },\n"
    "  \"notes\": \"\",            // 简要说明从对话中提取到了什么信息\n"
    "  \"missing_fields\": []      // 列表：仍然缺失的必填字段，如 [\"cwe_id\", \"binary_filename\"]\n"
    "}\n\n"
    "完整的历史对话如下：\n"
    "<<<\n"
    "{user_input}\n"
    ">>>\n"
)


EXTRACTION_PROMPT_REPRODUCTION = (
    "你是一个专业的安全分析助手，擅长从用户的多轮对话中提取和维护结构化参数。\n"
    "当前为【漏洞复现模式】，用户希望复现已知的CVE漏洞。\n\n"
    "需要提取的关键字段（必填）：\n"
    "1. cve_id：形如 CVE-YYYY-NNNN 的编号（如 CVE-2024-12345）\n"
    "   注意区分大小写，必须是有效的CVE编号格式\n\n"
    "2. binary_filename：目标固件或二进制文件名称\n"
    "   可以是文件名（如 httpd、firmware.bin）、设备型号（如 DIR-878）、\n"
    "   产品名称（如 DSL-AC3100）、厂商名称（如 QNAP）等任何能定位目标的信息\n\n"
    "【历史已收集的参数】：\n"
    "{existing_params}\n\n"
    "【重要】：\n"
    "1. 请保留历史已收集的参数，除非本次用户明确要修改\n"
    "2. 新的用户输入可能只是补充缺失的信息，不要覆盖已有信息\n"
    "3. 仔细分析所有历史对话，综合提取完整参数\n\n"
    "严格按照下述 JSON 模板输出（禁止输出额外解释或Markdown标记）：\n"
    "{\n"
    "  \"cve_id\": \"\",          // 字符串，若仍未找到保持为空\n"
    "  \"binary_filename\": \"\", // 字符串，若仍未找到保持为空\n"
    "  \"confidence\": {\n"
    "    \"cve_id\": \"high|medium|low|none\",\n"
    "    \"binary_filename\": \"high|medium|low|none\"\n"
    "  },\n"
    "  \"notes\": \"\",            // 简要说明从对话中提取到了什么信息\n"
    "  \"missing_fields\": []      // 列表：仍然缺失的必填字段，如 [\"cve_id\", \"binary_filename\"]\n"
    "}\n\n"
    "完整的历史对话如下：\n"
    "<<<\n"
    "{user_input}\n"
    ">>>\n"
)


class ParameterAgent(Agent):
    """调用大模型抽取漏洞分析所需的关键参数。
    
    支持两种工作模式：
    - REPRODUCTION: 漏洞复现模式，需要 CVE ID + binary_filename
    - DISCOVERY: 漏洞挖掘模式，需要 CWE ID + binary_filename
    """

    # 不同模式下的必填字段
    REQUIRED_FIELDS_REPRODUCTION = ("cve_id", "binary_filename")
    REQUIRED_FIELDS_DISCOVERY = ("cwe_id", "binary_filename")

    def __init__(self, chat_model: ChatModel, work_mode: WorkMode = WorkMode.DISCOVERY) -> None:
        super().__init__(chat_model)
        self.work_mode = work_mode

    @property
    def required_fields(self) -> Tuple[str, ...]:
        """根据工作模式返回必填字段"""
        if self.work_mode == WorkMode.REPRODUCTION:
            return self.REQUIRED_FIELDS_REPRODUCTION
        return self.REQUIRED_FIELDS_DISCOVERY

    def process(self, query: str, existing_params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:  # type: ignore[override]
        """向大模型请求解析结果，并结合启发式兜底逻辑。
        
        Args:
            query: 用户输入的查询文本（可以是多轮对话的累积）
            existing_params: 历史已收集的参数字典
        """
        query = (query or "").strip()
        existing_params = existing_params or {}
        logger.info("ParameterAgent processing query (mode=%s): %s", self.work_mode.value, query)
        logger.debug("Existing params: %s", existing_params)
        
        raw_response: Optional[str] = None
        errors: List[str] = []
        llm_result: Dict[str, Any] = {}

        if not query:
            errors.append("empty_query")
        else:
            # 构建已收集参数的描述
            existing_params_desc = self._format_existing_params(existing_params)
            
            # 根据工作模式选择不同的提取Prompt
            if self.work_mode == WorkMode.DISCOVERY:
                prompt = EXTRACTION_PROMPT_DISCOVERY.replace("{user_input}", query)
            else:
                prompt = EXTRACTION_PROMPT_REPRODUCTION.replace("{user_input}", query)
            
            # 插入已收集的参数信息
            prompt = prompt.replace("{existing_params}", existing_params_desc)
            
            try:
                raw_response = self.chat_model.chat(prompt)
                llm_result = self._parse_response(raw_response)
            except Exception as exc:  # pylint: disable=broad-except
                logger.error("ParameterAgent LLM call failed: %s", exc)
                errors.append(str(exc))
                llm_result = {}

        normalized = self._normalize_result(llm_result)
        heuristic = self._heuristic_extract(query)

        # 合并启发式提取结果
        for field in self.required_fields:
            if not normalized.get(field) and heuristic.get(field):
                normalized[field] = heuristic[field]
        
        # 额外字段也尝试合并（如 vendor）
        for field in ["vendor", "cve_id", "cwe_id"]:
            if not normalized.get(field) and heuristic.get(field):
                normalized[field] = heuristic[field]

        missing = [field for field in self.required_fields if not normalized.get(field)]
        normalized["missing_fields"] = missing
        normalized["work_mode"] = self.work_mode.value
        
        if errors:
            normalized.setdefault("errors", []).extend(errors)
        if raw_response is not None:
            normalized.setdefault("raw_response", raw_response)

        logger.info("ParameterAgent result: %s", normalized)
        return normalized

    def _format_existing_params(self, params: Dict[str, Any]) -> str:
        """格式化已收集的参数为易读的文本描述"""
        if not params:
            return "（暂无已收集的参数）"
        
        lines = []
        for key, value in params.items():
            if value and str(value).strip():
                # 为CWE ID添加描述
                if key == "cwe_id" and value in CWE_DESCRIPTIONS:
                    lines.append(f"  - {key}: {value} ({CWE_DESCRIPTIONS[value]})")
                else:
                    lines.append(f"  - {key}: {value}")
        
        if not lines:
            return "（暂无已收集的参数）"
        
        return "\n".join(lines)

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
            "cwe_id": (result or {}).get("cwe_id", "").strip() if result else "",
            "binary_filename": (result or {}).get("binary_filename", "").strip() if result else "",
            "vendor": (result or {}).get("vendor", "").strip() if result else "",
            "confidence": (result or {}).get("confidence", {}),
            "notes": (result or {}).get("notes", ""),
            "missing_fields": (result or {}).get("missing_fields", []),
        }
        # 标准化 CWE ID 格式
        if normalized["cwe_id"]:
            normalized["cwe_id"] = self._normalize_cwe_id(normalized["cwe_id"])
        return normalized

    def _normalize_cwe_id(self, cwe_id: str) -> str:
        """标准化CWE ID格式为 CWE-XXX"""
        cwe_id = cwe_id.strip().upper()
        # 如果只是数字，添加CWE-前缀
        if cwe_id.isdigit():
            return f"CWE-{cwe_id}"
        # 如果已经是CWE-XXX格式
        match = re.match(r"CWE[- ]?(\d+)", cwe_id, re.IGNORECASE)
        if match:
            return f"CWE-{match.group(1)}"
        return cwe_id

    def _heuristic_extract(self, query: str) -> Dict[str, Optional[str]]:
        """启发式提取参数"""
        if not query:
            return {"cve_id": None, "cwe_id": None, "binary_filename": None, "vendor": None}

        # 提取CVE ID
        cve_match = re.search(r"CVE-\d{4}-\d{4,7}", query, re.IGNORECASE)
        cve_id = cve_match.group(0).upper() if cve_match else None

        # 提取CWE ID
        cwe_match = re.search(r"CWE[- ]?(\d+)", query, re.IGNORECASE)
        cwe_id = f"CWE-{cwe_match.group(1)}" if cwe_match else None
        
        # 如果没有明确的CWE ID，尝试从漏洞类型描述推断
        if not cwe_id:
            cwe_id = self._infer_cwe_from_description(query)

        # 提取厂商名称
        vendor = None
        vendor_patterns = [
            r"(?:厂商|vendor|manufacturer)[:\s：]*([A-Za-z][\w\-]+)",
            r"\b(Netgear|D-Link|TP-Link|ASUS|Tenda|Linksys|Cisco|Huawei|ZTE|Xiaomi|Ruijie|H3C|TOTOLINK|TRENDnet|Buffalo|Belkin|Synology|QNAP|Ubiquiti)\b",
        ]
        for pattern in vendor_patterns:
            match = re.search(pattern, query, re.IGNORECASE)
            if match:
                vendor = match.group(1).strip()
                break

        # 提取二进制文件名
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

        return {"cve_id": cve_id, "cwe_id": cwe_id, "binary_filename": binary_name, "vendor": vendor}

    def _infer_cwe_from_description(self, query: str) -> Optional[str]:
        """从漏洞类型描述推断CWE ID"""
        query_lower = query.lower()
        
        # 漏洞类型描述到CWE的映射
        description_to_cwe = [
            # 命令注入
            (["命令注入", "command injection", "os command", "系统命令", "shell注入"], "CWE-78"),
            # 缓冲区溢出
            (["缓冲区溢出", "buffer overflow", "栈溢出", "stack overflow", "stack-based"], "CWE-121"),
            (["堆溢出", "heap overflow", "heap-based"], "CWE-122"),
            (["缓冲区", "buffer"], "CWE-120"),
            # 越界
            (["越界写", "out-of-bounds write", "oob write"], "CWE-787"),
            (["越界读", "out-of-bounds read", "oob read"], "CWE-125"),
            # 路径遍历
            (["路径遍历", "path traversal", "目录遍历", "directory traversal", "../"], "CWE-22"),
            # 格式化字符串
            (["格式化字符串", "format string"], "CWE-134"),
            # 整数溢出
            (["整数溢出", "integer overflow"], "CWE-190"),
            (["整数下溢", "integer underflow"], "CWE-191"),
            # UAF
            (["use after free", "uaf", "释放后使用"], "CWE-416"),
            (["double free", "双重释放"], "CWE-415"),
            # 空指针
            (["空指针", "null pointer", "nullptr"], "CWE-476"),
            # 认证相关
            (["硬编码", "hard-coded", "hardcoded", "内置密码"], "CWE-798"),
            (["认证绕过", "authentication bypass", "未授权"], "CWE-287"),
            # 注入
            (["sql注入", "sql injection"], "CWE-89"),
            (["xss", "跨站脚本"], "CWE-79"),
            # SSRF/XXE
            (["ssrf", "服务端请求伪造"], "CWE-918"),
            (["xxe", "xml外部实体"], "CWE-611"),
        ]
        
        for keywords, cwe in description_to_cwe:
            for keyword in keywords:
                if keyword in query_lower:
                    logger.debug("Inferred CWE from description: %s -> %s", keyword, cwe)
                    return cwe
        
        return None


class ParameterCollector:
    """在系统运行前与用户交互，收集必要的参数。
    
    支持两种工作模式：
    - REPRODUCTION: 漏洞复现模式
    - DISCOVERY: 漏洞挖掘模式
    """

    FIELD_PROMPTS_REPRODUCTION = {
        "cve_id": "未识别到明确的 CVE ID。请提供形如 CVE-2024-12345 的编号，便于后续检索。",
        "binary_filename": "未识别到目标固件/二进制名称。请说明需要分析的设备或二进制文件名称。",
    }
    
    FIELD_PROMPTS_DISCOVERY = {
        "cwe_id": (
            "未识别到明确的 CWE 类型。请提供漏洞类型，例如：\n"
            "- CWE-78（命令注入）\n"
            "- CWE-120（缓冲区溢出）\n"
            "- CWE-22（路径遍历）\n"
            "- 或直接描述漏洞类型，如'命令注入'、'栈溢出'等"
        ),
        "binary_filename": "未识别到目标固件/二进制名称。请说明需要分析的设备或二进制文件名称。",
    }

    def __init__(
        self,
        chat_id: str,
        send_callback: Callable[[Dict[str, Any]], Awaitable[None]],
        chat_model: ChatModel,
        work_mode: WorkMode = WorkMode.DISCOVERY,
        parameter_agent: Optional[ParameterAgent] = None
    ) -> None:
        self.chat_id = str(chat_id)
        self.work_mode = work_mode
        self.agent = parameter_agent or ParameterAgent(chat_model, work_mode=work_mode)
        self._send_callback = send_callback
        
        # 根据工作模式初始化参数和提示词
        self.field_prompts = (
            self.FIELD_PROMPTS_REPRODUCTION if work_mode == WorkMode.REPRODUCTION 
            else self.FIELD_PROMPTS_DISCOVERY
        )
        self.parameters: Dict[str, Optional[str]] = {
            field: None for field in self.agent.required_fields
        }
        # 额外存储可选参数（如vendor用于漏洞挖掘时搜索历史CVE）
        self.optional_parameters: Dict[str, Optional[str]] = {
            "vendor": None,
            "cve_id": None if work_mode == WorkMode.DISCOVERY else None,
            "cwe_id": None if work_mode == WorkMode.REPRODUCTION else None,
        }
        
        self.prompted_fields: set[str] = set()
        self.initial_message_sent = False
        self.completed = False
        self.history: List[str] = []
        self.original_query: Optional[str] = None

    def update_sender(self, send_callback: Callable[[Dict[str, Any]], Awaitable[None]]) -> None:
        self._send_callback = send_callback

    async def handle_message(self, message: str) -> Dict[str, Any]:
        """处理用户消息并收集参数
        
        此方法会将历史对话累积后一起传给LLM进行分析，确保对话记忆。
        """
        message = (message or "").strip()
        if message:
            self.history.append(f"用户: {message}")
            if self.original_query is None:
                self.original_query = message
        
        if not self.initial_message_sent:
            mode_desc = "漏洞挖掘" if self.work_mode == WorkMode.DISCOVERY else "漏洞复现"
            await self._send(f"参数收集智能体已启动（{mode_desc}模式），正在解析您的需求...", message_type="header1")
            self.initial_message_sent = True

        # 将所有历史对话拼接成完整上下文
        full_context = "\n".join(self.history)
        
        # 传入已收集的参数，让LLM保持记忆
        current_params = {**self.parameters, **self.optional_parameters}
        result = self.agent.process(full_context, existing_params=current_params)
        
        # 获取LLM的notes，用于向用户反馈
        llm_notes = result.get("notes", "")
        
        # 更新必填参数（只更新非空值）
        for field in self.agent.required_fields:
            value = result.get(field)
            if isinstance(value, str) and value.strip():
                old_value = self.parameters.get(field)
                self.parameters[field] = value.strip()
                # 记录参数更新
                if old_value != value.strip():
                    logger.info("Parameter updated: %s = %s (was: %s)", field, value.strip(), old_value)
        
        # 更新可选参数（只更新非空值）
        for field in self.optional_parameters:
            value = result.get(field)
            if isinstance(value, str) and value.strip():
                old_value = self.optional_parameters.get(field)
                self.optional_parameters[field] = value.strip()
                if old_value != value.strip():
                    logger.info("Optional parameter updated: %s = %s (was: %s)", field, value.strip(), old_value)

        missing = [field for field in self.agent.required_fields if not self.parameters.get(field)]

        if result.get("errors"):
            await self._send("⚠️ 参数解析时出现异常，已启用兜底策略。")

        # 构建状态摘要
        await self._send_status_summary(missing, llm_notes)

        if missing:
            # 构建更详细的缺失信息提示
            await self._send_missing_prompts(missing)
            
            return {
                "ready": False,
                "parameters": {**self.parameters, **self.optional_parameters},
                "missing": missing,
                "query": "\n".join(self.history),
                "work_mode": self.work_mode.value
            }

        # 所有参数收集完成
        if not self.completed:
            await self._send_completion_summary()
            self.completed = True

        return {
            "ready": True,
            "parameters": {**self.parameters, **self.optional_parameters},
            "missing": [],
            "query": "\n".join(self.history),
            "work_mode": self.work_mode.value
        }

    async def _send_status_summary(self, missing: List[str], llm_notes: str) -> None:
        """发送当前参数收集状态摘要"""
        collected = []
        
        # 汇总已收集的必填参数
        for field in self.agent.required_fields:
            value = self.parameters.get(field)
            if value:
                if field == "cwe_id" and value in CWE_DESCRIPTIONS:
                    collected.append(f"✓ {self._get_field_display_name(field)}: {value} ({CWE_DESCRIPTIONS[value]})")
                else:
                    collected.append(f"✓ {self._get_field_display_name(field)}: {value}")
        
        # 汇总已收集的可选参数
        for field, value in self.optional_parameters.items():
            if value:
                collected.append(f"✓ {self._get_field_display_name(field)}（可选）: {value}")
        
        # 汇总缺失的参数
        missing_names = [f"✗ {self._get_field_display_name(field)}" for field in missing]
        
        if collected or missing_names:
            status_lines = ["📋 当前参数收集状态："]
            if collected:
                status_lines.extend(collected)
            if missing_names:
                status_lines.append("\n仍需补充：")
                status_lines.extend(missing_names)
            
            if llm_notes:
                status_lines.append(f"\n💡 {llm_notes}")
            
            await self._send("\n".join(status_lines))

    async def _send_missing_prompts(self, missing: List[str]) -> None:
        """发送缺失参数的详细提示"""
        prompts = []
        for field in missing:
            if field not in self.prompted_fields:
                prompt_text = self.field_prompts.get(field, f"请提供 {self._get_field_display_name(field)}")
                prompts.append(f"❓ {prompt_text}")
                self.prompted_fields.add(field)
        
        if prompts:
            await self._send("\n\n".join(prompts))
        else:
            # 已经提示过所有缺失字段，给出更友好的提示
            missing_display = "、".join([self._get_field_display_name(f) for f in missing])
            await self._send(
                f"⚠️ 仍缺少以下必要信息：{missing_display}\n\n"
                f"请提供上述信息后，系统将继续执行分析。您可以用自然语言描述，无需严格遵循格式。"
            )

    async def _send_completion_summary(self) -> None:
        """发送参数收集完成摘要"""
        if self.work_mode == WorkMode.DISCOVERY:
            cwe_desc = CWE_DESCRIPTIONS.get(self.parameters.get('cwe_id', ''), '')
            summary = [
                "✅ 参数收集完成（漏洞挖掘模式）",
                f"  • CWE 类型: {self.parameters.get('cwe_id', 'N/A')}"
            ]
            if cwe_desc:
                summary.append(f"    {cwe_desc}")
            summary.append(f"  • 目标二进制/固件: {self.parameters.get('binary_filename', 'N/A')}")
            
            if self.optional_parameters.get('vendor'):
                summary.append(f"  • 厂商: {self.optional_parameters['vendor']}")
            if self.optional_parameters.get('cve_id'):
                summary.append(f"  • 参考CVE: {self.optional_parameters['cve_id']}")
            
            summary.append("\n🚀 系统将继续执行漏洞挖掘分析...")
        else:
            summary = [
                "✅ 参数收集完成（漏洞复现模式）",
                f"  • CVE ID: {self.parameters.get('cve_id', 'N/A')}",
                f"  • 目标二进制/固件: {self.parameters.get('binary_filename', 'N/A')}",
                "\n🚀 系统将继续执行漏洞复现分析..."
            ]
        
        await self._send("\n".join(summary), message_type="header2")

    def _get_field_display_name(self, field: str) -> str:
        """获取字段的友好显示名称"""
        display_names = {
            "cve_id": "CVE编号",
            "cwe_id": "CWE类型",
            "binary_filename": "目标固件/二进制",
            "vendor": "设备厂商",
        }
        return display_names.get(field, field)

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