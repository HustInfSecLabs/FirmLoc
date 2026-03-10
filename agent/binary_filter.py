from agent.base import Agent
from agent.parameter_agent import CWE_SENSITIVE_BINARIES, CWE_DESCRIPTIONS
from model.base import ChatModel
from pathlib import Path
from log import logger
from tools.binary_diff_detector import find_modified_binaries, format_diff_summary, get_modified_binaries_list
import json
import re
import tiktoken
import os
import subprocess
import stat

# 漏洞复现模式的Prompt（基于CVE信息筛选）
PROMPT_REPRODUCTION = """You are a security analyst who specializes in analyzing binary files that may have vulnerabilities based on the names of affected services/programs and their vulnerability types mentioned in CVE descriptions and other information.
You need to find relevant binary files that may have vulnerabilities in the executable binary list [directory] (extracted from the firmware directory) and CVE information [CVE details] of the {binary_filename} device provided below.

Strictly output **raw JSON only** in the following format (do NOT wrap with Markdown code fences):
{{
"status": "success" | "error",  // use "error" when unsure
"message": "Analysis description",
"suspicious_binaries": [
{{
"binary_name": "Binary file name xxx",
"binary_path": "Binary file path",
"reason": "Determine the reason why the file may have a vulnerability"
}},
{{
"binary_name": "Binary file name yyy",
"binary_path": "Binary file path",
"reason": "Determine the reason why the file may have a vulnerability"
}}
]
}}

Rules:
- suspicious_binaries can output up to 3, sorted by relevance (most suspicious first).
- If a suspicious binary cannot be determined, set status to "error" and return an empty suspicious_binaries array with a clear message.
- Do not include any extra text, Markdown, or explanations outside the JSON.

Example error message output:
{{
"status": "error",
"message": "According to CVE information, no relevant suspicious binary files were found in the provided directory",
"suspicious_binaries": []
}}

Now the following is a real application scenario. Please analyze the following information and output the analysis results strictly in accordance with the format requirements.

[CVE details]
{cve_details}
[CVE details end]

[directory]
{directory}
[directory end]
Please make sure that the file path really exists.
"""

# 漏洞挖掘模式的Prompt（基于CWE类型筛选）
PROMPT_DISCOVERY = """You are a security analyst specializing in vulnerability discovery. Your task is to identify binary files that are most likely to contain {cwe_type} vulnerabilities.

**Vulnerability Type Information:**
- CWE ID: {cwe_id}
- Description: {cwe_description}

**CWE-Specific Analysis Guidelines:**
{cwe_guidelines}

**Historical Reference CVEs (if available):**
{reference_cves}

**Target Device:** {binary_filename}

Your task: Analyze the executable binary list below and identify binaries that are most likely to contain {cwe_type} vulnerabilities.

Strictly output **raw JSON only** in the following format (do NOT wrap with Markdown code fences):
{{
"status": "success" | "error",
"message": "Analysis description",
"suspicious_binaries": [
{{
"binary_name": "Binary file name",
"binary_path": "Binary file path",
"reason": "Explain why this binary is likely to have {cwe_type} vulnerability",
"priority": "high|medium|low"
}}
]
}}

Rules:
- suspicious_binaries can output up to 5, sorted by priority (highest first).
- Focus on binaries that:
  * Handle external input (network, files, user input)
  * Match the vulnerability pattern for {cwe_id}
  * Are common targets for this vulnerability type
- If no suspicious binaries can be determined, set status to "error" with a clear message.
- Do not include any extra text, Markdown, or explanations outside the JSON.

[directory]
{directory}
[directory end]
Please make sure that the file path really exists.
"""

# CWE类型特定的分析指南
CWE_ANALYSIS_GUIDELINES = {
    "CWE-78": """
- Focus on binaries that execute shell commands (system(), popen(), exec*)
- Look for web servers (httpd, lighttpd, goahead, boa, mini_httpd, uhttpd)
- Look for CGI handlers and scripts processors
- Network services that parse user input and pass to system commands
- Configuration utilities that accept user parameters
""",
    "CWE-77": """
- Similar to CWE-78, focus on command execution
- Look for binaries using shell interpreters
- Configuration management tools
""",
    "CWE-120": """
- Focus on binaries handling buffer operations (strcpy, memcpy, sprintf)
- Network daemons (httpd, ftpd, telnetd, sshd)
- Protocol parsers (upnpd, dnsd, dhcpd)
- Firmware update handlers
""",
    "CWE-121": """
- Focus on binaries with local buffer operations
- Look for parsers and decoders
- Network services processing structured data
""",
    "CWE-122": """
- Focus on binaries with dynamic memory allocation
- Complex parsers (XML, JSON, config files)
- Media/file format handlers
""",
    "CWE-22": """
- Focus on file servers and upload handlers
- Web servers with file access functionality
- FTP servers (ftpd, vsftpd)
- File management utilities
""",
    "CWE-787": """
- Focus on array/buffer write operations
- Network packet handlers
- Protocol decoders
- Media file parsers
""",
    "CWE-125": """
- Focus on array/buffer read operations
- Data parsers and format handlers
- Network data processors
""",
    "CWE-416": """
- Focus on complex state management
- Session handlers
- Connection managers
- Resource cleanup code
""",
    "CWE-798": """
- Focus on authentication modules
- Login handlers
- Configuration files with embedded credentials
- Admin interfaces
""",
}
class BinaryFilterAgent(Agent):
    """用于筛选可能存在漏洞的二进制文件的Agent"""
    
    def __init__(self, chat_model: ChatModel) -> None:
        super().__init__(chat_model)
        
    def _get_directory_structure(self, directory_path: str) -> str:
        # 使用du -ah命令获取目录结构
        try:
            result = subprocess.run(
                ['du','-ah', '.'],
                cwd=Path(directory_path),
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except Exception as e:
            raise RuntimeError(f"执行du -ah命令获取目录结构时发生错误: {str(e)}")
    def _is_ida_analysable(self, file_path: Path) -> bool:
        """
        判断文件是否为 IDA 可以分析的二进制类型。
        优先通过读取文件头（magic bytes）判断常见格式（ELF、PE、Mach-O、脚本 shebang 等），
        若无法确定则回退到调用系统 `file` 命令做检测（如果可用）。
        """
        try:
            with open(file_path, 'rb') as f:
                header = f.read(8)
        except (OSError, ValueError):
            return False

        # ELF: 0x7f 'E' 'L' 'F'
        if header.startswith(b'\x7fELF'):
            return True
        # PE (Windows executable and DLL): 'MZ'
        if header.startswith(b'MZ'):
            return True
        # Mach-O magic numbers
        mach_magic = [b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe']
        if header[:4] in mach_magic:
            return True
        # Script with shebang
        if header.startswith(b'#!'):
            return True

        # Fallback: use `file` command if available to detect shared object / executable descriptions
        try:
            result = subprocess.run(['file', '-b', str(file_path)], capture_output=True, text=True, check=False)
            desc = result.stdout.lower()
            # 包含这些关键字的通常是可分析的二进制/共享库/可执行文件
            keywords = ['elf', 'pe32', 'ms-dos', 'mach-o', 'shared object', 'executable', 'dynamically linked']
            if any(k in desc for k in keywords):
                return True
        except Exception:
            # 忽略 file 调用的任何错误，返回 False
            pass

        return False

    def _get_executable_binaries(self, directory_path: str) -> str:
        """
        获取所有可执行的二进制文件（包括没有执行位但是 IDA 可分析的文件）
        
        固件提取后，很多二进制文件会丢失执行权限位，因此不能只依赖执行位判断。
        改进策略：
        1. 优先通过文件格式判断（ELF/PE/Mach-O等）
        2. 如果无法通过格式判断，再检查执行权限位
        3. 过滤掉明显的非二进制文件（如 .txt, .sh, .conf 等）
        """
        executable_files = []
        directory = Path(directory_path)
        
        # 排除的文件扩展名（配置文件、文本文件、脚本等）
        excluded_extensions = {
            '.txt', '.md', '.conf', '.cfg', '.xml', '.json', '.yaml', '.yml',
            '.html', '.htm', '.css', '.js', '.log', '.ini', '.properties',
            '.sh', '.py', '.pl', '.rb', '.lua',  # 脚本文件
            '.list', '.control', '.pat',  # opkg 和配置文件
        }

        for root, _, files in os.walk(directory_path):
            for filename in files:
                file_path = Path(root) / filename
                
                # 检查文件扩展名，跳过明显的非二进制文件
                file_ext = file_path.suffix.lower()
                if file_ext in excluded_extensions:
                    continue
                
                try:
                    stat_result = file_path.stat()
                except (OSError, ValueError):
                    continue

                if not stat.S_ISREG(stat_result.st_mode):
                    continue

                # 策略1: 优先通过文件格式判断（这样能捕获没有执行位的二进制文件）
                try:
                    is_analysable = self._is_ida_analysable(file_path)
                except Exception:
                    is_analysable = False
                
                # 策略2: 检查执行权限位（作为补充判断）
                has_exec_bit = bool(stat_result.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                
                # 只要满足任一条件就认为是可执行二进制
                if is_analysable or has_exec_bit:
                    try:
                        relative_path = file_path.relative_to(directory)
                    except ValueError:
                        relative_path = file_path
                    executable_files.append(str(relative_path))

        if not executable_files:
            return "未在提供的目录中找到可执行二进制文件。"

        executable_files.sort()
        return "\n".join(executable_files)

    def _extract_json_block(self, response: str) -> str:
        """从模型响应中提取 JSON 字符串，支持 markdown 代码块和裸 JSON。"""
        if not response:
            return ""

        json_match = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", response, re.IGNORECASE)
        if json_match:
            return json_match.group(1).strip()

        brace_match = re.search(r"({[\s\S]+})", response)
        if brace_match:
            return brace_match.group(1).strip()

        return ""

    def _normalize_process_result(self, process_result: dict) -> tuple:
        """
        校验并规范化模型返回，确保字段齐全且类型正确。
        返回 (normalized_dict, warning_str|None)
        """
        if not isinstance(process_result, dict):
            return None, "响应不是 JSON 对象"

        status = process_result.get("status", "error")
        if status not in {"success", "error"}:
            status = "error"

        message = str(process_result.get("message", "")).strip()
        suspicious_list = process_result.get("suspicious_binaries", [])
        if not isinstance(suspicious_list, list):
            suspicious_list = []

        normalized_binaries = []
        for item in suspicious_list[:3]:
            if not isinstance(item, dict):
                continue
            binary_name = str(item.get("binary_name", "")).strip()
            binary_path = str(item.get("binary_path", "")).strip()
            reason = str(item.get("reason", "")).strip() or "模型未提供原因"

            if not binary_name and binary_path:
                binary_name = Path(binary_path).name

            # 至少需要 binary_path 或 binary_name 之一
            if not binary_name and not binary_path:
                continue

            normalized_binaries.append({
                "binary_name": binary_name,
                "binary_path": binary_path,
                "reason": reason
            })

        # 如果标记 success 但没有可疑列表，降级为 error
        warning = None
        if status == "success" and not normalized_binaries:
            warning = "模型返回 success 但未提供可疑二进制，已降级为 error"
            status = "error"
            if not message:
                message = warning

        normalized = {
            "status": status,
            "message": message or "模型未给出说明",
            "suspicious_binaries": normalized_binaries
        }

        return normalized, warning

    def _build_retry_prompt(self, base_prompt: str, last_error: str) -> str:
        """构造重试提示，要求模型仅返回合规 JSON。"""
        retry_hint = (
            "\n\n上一次回复未满足 JSON 结构要求，错误原因: "
            f"{last_error}。请严格输出纯 JSON，字段包括 status/message/suspicious_binaries，"
            "不使用 Markdown 代码块，若无法确定则返回 status=\"error\" 且 suspicious_binaries 为空数组。"
        )
        return base_prompt + retry_hint

    def _chat_and_parse_with_retry(self, prompt: str, max_attempts: int = 2) -> tuple:
        """调用大模型并解析，失败时自动追加一次纠错重试。"""
        errors = []
        last_raw = ""

        for attempt in range(max_attempts):
            raw_response = self.chat_model.chat(prompt)
            last_raw = raw_response

            json_str = self._extract_json_block(raw_response)
            if not json_str:
                errors.append("未找到 JSON 块")
                prompt = self._build_retry_prompt(prompt, errors[-1])
                continue

            try:
                process_result = json.loads(json_str)
            except Exception as e:
                errors.append(f"JSON 解析失败: {str(e)}")
                prompt = self._build_retry_prompt(prompt, errors[-1])
                continue

            normalized, warning = self._normalize_process_result(process_result)
            if normalized:
                # 检查是否返回了有效结果
                has_binaries = bool(normalized.get("suspicious_binaries"))
                status_is_success = normalized.get("status") == "success"
                
                # 如果是最后一次尝试，或者返回了有效的可疑二进制列表，则接受结果
                is_last_attempt = (attempt == max_attempts - 1)
                
                if has_binaries or status_is_success or is_last_attempt:
                    if warning:
                        normalized["message"] = f"{normalized.get('message', '')} | {warning}".strip(" |")
                    return normalized, raw_response
                
                # 否则，如果模型返回了 error 且没有可疑二进制，触发重试
                if not has_binaries and not status_is_success:
                    error_msg = f"模型返回 status=error 且未找到可疑二进制。原因: {normalized.get('message', '未知')}"
                    errors.append(error_msg)
                    logger.warning(f"第 {attempt + 1} 次尝试: {error_msg}，将进行重试...")
                    
                    # 构造更强烈的重试提示
                    retry_hint = (
                        "\n\n上一次分析未能找到可疑的二进制文件。"
                        "请重新仔细分析提供的二进制列表和漏洞信息，"
                        "尝试从以下角度寻找可能存在漏洞的二进制文件："
                        "\n1. 文件名中包含与漏洞相关的服务名称（如httpd、cgi、admin等）"
                        "\n2. 路径中包含网络服务相关目录（如/usr/sbin、/bin、/usr/bin等）"
                        "\n3. 常见的网络服务程序和守护进程"
                        "\n\n如果确实无法找到明确的可疑文件，请至少返回2-3个最有可能相关的二进制文件。"
                        "\n严格按照JSON格式输出，status设为\"success\"，并在suspicious_binaries数组中至少包含1-3个条目。"
                    )
                    prompt = prompt + retry_hint
                    continue

            errors.append(warning or "模型返回内容无法规范化")
            prompt = self._build_retry_prompt(prompt, errors[-1])

        fallback_message = "; ".join(errors) if errors else "模型响应无法解析"
        return {
            "status": "error",
            "message": f"模型响应无法解析: {fallback_message}",
            "suspicious_binaries": []
        }, last_raw
    
    def _heuristic_filter_by_cwe(self, executable_binaries: str, cwe_id: str) -> list:
        """
        基于CWE类型的启发式筛选，返回优先级排序的二进制列表
        """
        if not cwe_id or not executable_binaries:
            return []
        
        sensitive_keywords = CWE_SENSITIVE_BINARIES.get(cwe_id.upper(), [])
        if not sensitive_keywords:
            return []
        
        binaries = executable_binaries.strip().split('\n')
        scored_binaries = []
        
        for binary_path in binaries:
            binary_name = Path(binary_path).name.lower()
            score = 0
            matched_keywords = []
            
            for keyword in sensitive_keywords:
                if keyword.lower() in binary_name:
                    score += 2
                    matched_keywords.append(keyword)
                elif keyword.lower() in binary_path.lower():
                    score += 1
                    matched_keywords.append(keyword)
            
            if score > 0:
                scored_binaries.append({
                    "path": binary_path,
                    "name": Path(binary_path).name,
                    "score": score,
                    "keywords": matched_keywords
                })
        
        # 按分数降序排序
        scored_binaries.sort(key=lambda x: x["score"], reverse=True)
        return scored_binaries[:10]  # 返回前10个
    
    def _heuristic_filter_by_cve(self, executable_binaries: str, cve_details: str) -> list:
        """
        基于CVE描述的启发式筛选，提取CVE中提到的服务/程序名称
        
        从CVE描述中提取常见的服务名、程序名，然后在二进制列表中匹配
        """
        if not cve_details or not executable_binaries:
            return []
        
        # 常见的服务/程序关键词（优先级从高到低）
        common_services = {
            # Web服务器
            "httpd": 15, "apache": 15, "nginx": 15, "lighttpd": 15, 
            "goahead": 15, "boa": 15, "uhttpd": 15, "mini_httpd": 15,
            "thttpd": 15, "mongoose": 15,
            # CGI/脚本处理
            "cgi": 12, "cgi-bin": 12, "php": 10, "fcgi": 10,
            # FTP服务
            "ftpd": 15, "vsftpd": 15, "proftpd": 15, "pure-ftpd": 15,
            # 远程访问
            "sshd": 15, "telnetd": 15, "dropbear": 15,
            # 网络服务
            "upnpd": 12, "miniupnpd": 12, "samba": 12, "smbd": 12,
            "dhcpd": 10, "dnsmasq": 10, "hostapd": 10,
            # 其他常见服务
            "busybox": 8, "login": 10, "admin": 10, "config": 8,
            "setup": 10, "upgrade": 10, "update": 10,
        }
        
        # 从CVE描述中提取关键词
        cve_lower = cve_details.lower()
        extracted_keywords = {}
        
        for keyword, weight in common_services.items():
            if keyword in cve_lower:
                extracted_keywords[keyword] = weight
        
        # 如果没有提取到关键词，使用默认的高优先级服务
        if not extracted_keywords:
            logger.warning("CVE描述中未找到明确的服务名，使用默认优先级列表")
            extracted_keywords = {
                "httpd": 10, "cgi": 8, "ftpd": 8, "sshd": 8, 
                "telnetd": 8, "upnpd": 8, "admin": 6, "setup": 6
            }
        
        # 对二进制列表进行评分
        binaries = executable_binaries.strip().split('\n')
        scored_binaries = []
        
        for binary_path in binaries:
            binary_name = Path(binary_path).name.lower()
            binary_path_lower = binary_path.lower()
            score = 0
            matched_keywords = []
            
            for keyword, weight in extracted_keywords.items():
                if keyword in binary_name:
                    score += weight * 2  # 文件名匹配权重加倍
                    matched_keywords.append(keyword)
                elif keyword in binary_path_lower:
                    score += weight  # 路径匹配使用原权重
                    matched_keywords.append(keyword)
            
            if score > 0:
                scored_binaries.append({
                    "path": binary_path,
                    "name": Path(binary_path).name,
                    "score": score,
                    "keywords": list(set(matched_keywords))  # 去重
                })
        
        # 按分数降序排序
        scored_binaries.sort(key=lambda x: x["score"], reverse=True)
        
        logger.info(f"CVE启发式筛选: 从 {len(binaries)} 个二进制中找到 {len(scored_binaries)} 个匹配")
        return scored_binaries[:10]  # 返回前10个
    
    def _format_reference_cves(self, cve_details: str, max_cves: int = 5) -> str:
        """格式化参考CVE信息用于Prompt"""
        if not cve_details:
            return "No historical CVE references available."
        
        try:
            # 尝试解析JSON格式的CVE详情
            if isinstance(cve_details, str) and cve_details.strip().startswith('{'):
                cve_data = json.loads(cve_details)
                vulnerabilities = cve_data.get("vulnerabilities", [])[:max_cves]
                if vulnerabilities:
                    formatted = []
                    for vuln in vulnerabilities:
                        cve = vuln.get("cve", {})
                        cve_id = cve.get("id", "Unknown")
                        desc = ""
                        for d in cve.get("descriptions", []):
                            if d.get("lang") == "en":
                                desc = d.get("value", "")[:200]
                                break
                        formatted.append(f"- {cve_id}: {desc}...")
                    return "\n".join(formatted)
        except (json.JSONDecodeError, TypeError):
            pass
        
        # 如果是纯文本，直接截取前500字符
        if len(cve_details) > 500:
            return cve_details[:500] + "..."
        return cve_details
        
    def process(self, binary_filename: str, extracted_files_path: str, 
                cve_details: str = None, cwe_id: str = None, 
                work_mode: str = "reproduction", reference_cves: str = None,
                old_firmware_path: str = None, new_firmware_path: str = None,
                enable_diff_filter: bool = True) -> dict:
        """
        筛选可疑二进制文件
        
        Args:
            binary_filename: 目标设备/固件名称
            extracted_files_path: 提取的固件文件路径
            cve_details: CVE详情（漏洞复现模式使用）
            cwe_id: CWE编号（漏洞挖掘模式使用）
            work_mode: 工作模式 - "reproduction" 或 "discovery"
            reference_cves: 参考CVE信息（漏洞挖掘模式可选）
            old_firmware_path: 旧版本固件解压路径（用于差异检测）
            new_firmware_path: 新版本固件解压路径（用于差异检测）
            enable_diff_filter: 是否启用差异筛选（默认True）
        """
        try:
            logger.info(f"BinaryFilterAgent开始分析 (mode={work_mode}, cwe={cwe_id}, diff_filter={enable_diff_filter})...")
            
            # 第一步：获取所有可执行二进制文件
            all_executable_binaries = self._get_executable_binaries(extracted_files_path)
            logger.info(f"扫描到 {len(all_executable_binaries.strip().split(chr(10)))} 个可执行二进制文件")
            
            # 第二步：如果启用差异筛选且提供了两个固件路径，则先筛选出有差异的文件
            filtered_binaries = all_executable_binaries
            diff_info = None
            
            if enable_diff_filter and old_firmware_path and new_firmware_path:
                logger.info("开始检测两个版本之间的二进制文件差异...")
                
                # 将可执行二进制列表转换为路径列表
                binary_paths = [line.strip() for line in all_executable_binaries.strip().split('\n') if line.strip()]
                
                # 调用差异检测工具
                diff_result = find_modified_binaries(old_firmware_path, new_firmware_path, binary_paths)
                diff_info = diff_result
                
                # 打印差异摘要
                diff_summary = format_diff_summary(diff_result)
                logger.info(f"差异检测结果:\n{diff_summary}")
                
                # 获取修改过的文件列表（包含modified和added，不包含removed）
                modified_list = get_modified_binaries_list(diff_result, include_added=True, include_removed=False)
                
                if modified_list:
                    filtered_binaries = "\n".join(modified_list)
                    logger.info(f"筛选后保留 {len(modified_list)} 个有差异的二进制文件")
                else:
                    logger.warning("未检测到任何二进制文件有差异，将分析所有二进制文件")
                    filtered_binaries = all_executable_binaries
            else:
                if not enable_diff_filter:
                    logger.info("差异筛选已禁用，将分析所有二进制文件")
                else:
                    logger.warning("未提供固件路径，跳过差异检测，将分析所有二进制文件")
            
            # 第三步：将筛选后的二进制列表提交给LLM分析
            logger.info(f"准备将 {len(filtered_binaries.strip().split(chr(10)))} 个文件提交给大模型进行智能筛选...")
            executable_binaries = filtered_binaries
            
            # 根据工作模式选择不同的筛选策略
            if work_mode == "discovery" and cwe_id:
                # 漏洞挖掘模式：基于CWE类型筛选
                prompt = self._build_discovery_prompt(
                    binary_filename, executable_binaries, cwe_id, reference_cves
                )
            else:
                # 漏洞复现模式：基于CVE信息筛选
                prompt = PROMPT_REPRODUCTION.format(
                    binary_filename=binary_filename,
                    directory=executable_binaries,
                    cve_details=cve_details or "No CVE details provided"
                )

            enc = tiktoken.get_encoding("cl100k_base")
            enc = tiktoken.encoding_for_model("gpt-4o")
            token_ids = enc.encode(prompt)
            logger.debug(f"Prompt token 数: {len(token_ids)}")
            
            process_result, raw_response = self._chat_and_parse_with_retry(prompt, max_attempts=2)
            logger.debug(f"大模型原始返回结果：{raw_response}")
            
            # 如果检测到了差异信息，将差异统计添加到返回结果中
            if diff_info:
                process_result["diff_statistics"] = {
                    "modified_count": len(diff_info.get("modified", [])),
                    "added_count": len(diff_info.get("added", [])),
                    "removed_count": len(diff_info.get("removed", [])),
                    "unchanged_count": len(diff_info.get("unchanged", []))
                }
            
            # 如果LLM没有返回结果，使用启发式筛选作为兜底
            if process_result.get("status") == "error" or not process_result.get("suspicious_binaries"):
                if work_mode == "discovery" and cwe_id:
                    # 漏洞挖掘模式：使用CWE启发式筛选
                    logger.info("LLM筛选无结果，使用CWE启发式筛选作为兜底...")
                    heuristic_results = self._heuristic_filter_by_cwe(executable_binaries, cwe_id)
                    if heuristic_results:
                        process_result = {
                            "status": "success",
                            "message": f"基于CWE-{cwe_id}启发式规则筛选出可疑二进制",
                            "suspicious_binaries": [
                                {
                                    "binary_name": r["name"],
                                    "binary_path": r["path"],
                                    "reason": f"匹配CWE敏感关键词: {', '.join(r['keywords'])}"
                                }
                                for r in heuristic_results[:5]
                            ]
                        }
                        logger.info(f"启发式筛选返回 {len(process_result['suspicious_binaries'])} 个可疑二进制")
                elif work_mode == "reproduction" and cve_details:
                    # 漏洞复现模式：基于CVE描述的启发式筛选
                    logger.info("LLM筛选无结果，使用CVE启发式筛选作为兜底...")
                    heuristic_results = self._heuristic_filter_by_cve(executable_binaries, cve_details)
                    if heuristic_results:
                        process_result = {
                            "status": "success",
                            "message": f"基于CVE描述启发式规则筛选出可疑二进制",
                            "suspicious_binaries": [
                                {
                                    "binary_name": r["name"],
                                    "binary_path": r["path"],
                                    "reason": f"匹配CVE关键词: {', '.join(r['keywords'])}"
                                }
                                for r in heuristic_results[:5]
                            ]
                        }
                        logger.info(f"启发式筛选返回 {len(process_result['suspicious_binaries'])} 个可疑二进制")

            return process_result
                
        except Exception as e:
            logger.error(f"BinaryFilterAgent处理过程发生错误: {str(e)}")
            return {
                "status": "error",
                "message": f"process failed: {str(e)}",
                "suspicious_binaries": []
            }
    
    def _build_discovery_prompt(self, binary_filename: str, executable_binaries: str,
                                 cwe_id: str, reference_cves: str = None) -> str:
        """构建漏洞挖掘模式的Prompt"""
        cwe_id_upper = cwe_id.upper()
        cwe_description = CWE_DESCRIPTIONS.get(cwe_id_upper, "Unknown vulnerability type")
        cwe_guidelines = CWE_ANALYSIS_GUIDELINES.get(cwe_id_upper, "Focus on binaries that handle external input and match common vulnerability patterns.")
        
        # 格式化参考CVE
        formatted_refs = self._format_reference_cves(reference_cves) if reference_cves else "No historical CVE references available."
        
        # 基于CWE的启发式预筛选提示
        heuristic_hints = self._heuristic_filter_by_cwe(executable_binaries, cwe_id)
        if heuristic_hints:
            hint_text = "\n**Pre-filtered candidates based on CWE patterns (for reference):**\n"
            for h in heuristic_hints[:5]:
                hint_text += f"- {h['name']} (matched: {', '.join(h['keywords'])})\n"
        else:
            hint_text = ""
        
        prompt = PROMPT_DISCOVERY.format(
            binary_filename=binary_filename,
            cwe_type=cwe_description,
            cwe_id=cwe_id_upper,
            cwe_description=cwe_description,
            cwe_guidelines=cwe_guidelines + hint_text,
            reference_cves=formatted_refs,
            directory=executable_binaries
        )
        
        return prompt