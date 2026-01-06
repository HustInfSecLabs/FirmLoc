from agent.base import Agent
from model.base import ChatModel
from pathlib import Path
import json
import re
import tiktoken
import os
import subprocess
import stat

PROMPT = """You are a security analyst who specializes in analyzing binary files that may have vulnerabilities based on the names of affected services/programs and their vulnerability types mentioned in CVE descriptions and other information.
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

# 下面是一个分析成功的示例输出:
# {{
#     "status": "success", 
#     "message": "发现1个可疑的二进制文件",
#     "suspicious_binaries": [
#         {{
#             "binary_name": "upnpd",
#             "binary_path": "/usr/sbin/upnpd",
#             "reason": "CVE-2021-27239描述中提到upnpd服务存在栈溢出漏洞"
#         }}
#     ]
# }}

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
                if warning:
                    normalized["message"] = f"{normalized.get('message', '')} | {warning}".strip(" |")
                return normalized, raw_response

            errors.append(warning or "模型返回内容无法规范化")
            prompt = self._build_retry_prompt(prompt, errors[-1])

        fallback_message = "; ".join(errors) if errors else "模型响应无法解析"
        return {
            "status": "error",
            "message": f"模型响应无法解析: {fallback_message}",
            "suspicious_binaries": []
        }, last_raw
        
    def process(self, binary_filename: str, extracted_files_path: str, cve_details: str) -> dict:
        try:
            print("开始分析并筛选可疑的二进制文件...")
            
            # 获取目录结构
            directory_structure = self._get_directory_structure(extracted_files_path)
            
            print(f"directory_structure:\n{directory_structure}")

            executable_binaries = self._get_executable_binaries(extracted_files_path)

            print(f"executable_binaries:\n{executable_binaries}")

            prompt = PROMPT.format(
                binary_filename = binary_filename,
                directory=executable_binaries,
                cve_details=cve_details
            )

            enc = tiktoken.get_encoding("cl100k_base")
            enc = tiktoken.encoding_for_model("gpt-4o")
            token_ids = enc.encode(prompt)
            print(f"Prompt token 数: {len(token_ids)}")
            process_result, raw_response = self._chat_and_parse_with_retry(prompt, max_attempts=2)
            print(f"大模型原始返回结果：{raw_response}")

            return process_result
                
        except Exception as e:
            print(f"BinaryFilterAgent处理过程发生错误: {str(e)}")
            return {
                "status": "error",
                "message": f"process failed: {str(e)}",
                "suspicious_binaries": []
            }