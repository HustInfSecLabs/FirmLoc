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

Strictly output in the following format:
{{
"status": "success/error",
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

Among them, suspicious_binaries can output up to 3, and the output results are sorted by relevance, with the most suspicious ones in the front. If the specific suspicious binary file cannot be determined, combine your knowledge base, vulnerability description and file directory to give the most likely binary file with the vulnerability.

If the directory structure passed in cannot be analyzed or no suspicious binary file related to the provided CVE is found in the directory, error and analysis results are returned.
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
        原来的逻辑只根据 Unix 执行位判断，这会漏掉很多没有执行位但仍然是二进制库的文件（例如 .so）。
        现在的逻辑为：如果文件有执行位，或被判断为 IDA 可分析类型，则视为“可执行二进制”并返回。
        """
        executable_files = []
        directory = Path(directory_path)

        for root, _, files in os.walk(directory_path):
            for filename in files:
                file_path = Path(root) / filename
                try:
                    stat_result = file_path.stat()
                except (OSError, ValueError):
                    continue

                if not stat.S_ISREG(stat_result.st_mode):
                    continue

                has_exec_bit = bool(stat_result.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                is_ida_bin = False
                # 如果没有执行位，尝试判断是否为可被 IDA 分析的二进制格式（比如 ELF shared objects）
                if not has_exec_bit:
                    try:
                        is_ida_bin = self._is_ida_analysable(file_path)
                    except Exception:
                        is_ida_bin = False

                if has_exec_bit or is_ida_bin:
                    try:
                        relative_path = file_path.relative_to(directory)
                    except ValueError:
                        relative_path = file_path
                    executable_files.append(str(relative_path))

        if not executable_files:
            return "未在提供的目录中找到可执行二进制文件。"

        executable_files.sort()
        lines = [path for path in executable_files]

        return "\n".join(lines)
        
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

            response = self.chat_model.chat(prompt)
            print(f"大模型原始返回结果：{response}")

            # 提取markdown格式的JSON块
            json_match = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", response, re.IGNORECASE)
            if json_match:
                json_result = json_match.group(1).strip()
            else:
                # 直接提取仅有大括号包围的JSON块
                json_match = re.search(r"({[\s\S]+})", response)
                if json_match:
                    json_result = json_match.group(1).strip()
                else:
                    raise ValueError("模型响应格式错误，无法解析为JSON或未找到有效的JSON数据")
            
            # print(f"提取出的json结果：{json_result}")

            process_result = json.loads(json_result)
            required_fields = ["status", "message", "suspicious_binaries"]
            if not all(field in process_result for field in required_fields):
                raise ValueError("响应的字段不完整")
                
            for binary in process_result["suspicious_binaries"]:
                required_binary_fields = ["binary_name", "binary_path", "reason"]
                if not all(field in binary for field in required_binary_fields):
                    raise ValueError("二进制文件信息字段不完整")
                    
            return process_result
                
        except Exception as e:
            print(f"BinaryFilterAgent处理过程发生错误: {str(e)}")
            return {
                "status": "error",
                "message": f"process failed: {str(e)}",
                "suspicious_binaries": []
            }