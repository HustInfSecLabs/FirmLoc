from agent.base import Agent
from model.base import ChatModel
import json
import re
import tiktoken
import os
import subprocess

PROMPT = """你是一个安全分析师，专门根据CVE描述等信息中提到的受影响的服务/程序名称及其漏洞类型，分析可能存在漏洞的二进制文件。
你需要根据下面提供的{binary_filename}设备的固件文件目录结构[directory]和CVE信息[CVE details]，在目录结构[directory]中寻找可能存在漏洞的相关二进制文件。

严格按照如下格式要求进行输出:
{{
    "status": "success/error",
    "message": "分析说明",
    "suspicious_binaries": [
        {{
            "binary_name": "二进制文件名xxx",
            "binary_path": "二进制文件路径",
            "reason": "判断该文件可能存在漏洞的原因"
        }},
        {{
            "binary_name": "二进制文件名yyy",
            "binary_path": "二进制文件路径",
            "reason": "判断该文件可能存在漏洞的原因"
        }}
    ]
}}

其中，suspicious_binaries最多输出5个，输出的结果按照相关的程度排序，最可疑的排列在前。如无法确定具体的可疑二进制文件，综合你的知识库、漏洞描述和文件目录给出最为可能的存在漏洞二进制文件。
下面是一个分析成功的示例输出:
{{
    "status": "success", 
    "message": "发现1个可疑的二进制文件",
    "suspicious_binaries": [
        {{
            "binary_name": "upnpd",
            "binary_path": "/usr/sbin/upnpd",
            "reason": "CVE-2021-27239描述中提到upnpd服务存在栈溢出漏洞"
        }}
    ]
}}

如果根据传入的目录结构无法分析或未在目录发现与提供的CVE相关可疑的二进制文件，返回error及分析结果。
示例错误信息输出：
{{
    "status": "error", 
    "message": "根据CVE信息，在提供的目录中未发现相关可疑的二进制文件",
    "suspicious_binaries": []
}}

现在下面是真实应用场景，请分析以下信息，严格按照格式要求输出分析结果。

[CVE details]
{cve_details}
[CVE details end]

[directory]
{directory}
[directory end]

"""

class BinaryFilterAgent(Agent):
    """用于筛选可能存在漏洞的二进制文件的Agent"""
    
    def __init__(self, chat_model: ChatModel) -> None:
        super().__init__(chat_model)
        
    def _get_directory_structure(self, directory_path: str) -> str:
        # 使用tree命令获取目录结构
        try:
            result = subprocess.run(
                ['tree','-A', directory_path],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except Exception as e:
            raise RuntimeError(f"执行tree命令获取目录结构时发生错误: {str(e)}")
        
    def process(self, binary_filename: str, extracted_files_path: str, cve_details: str) -> dict:
        try:
            print("开始分析并筛选可疑的二进制文件...")
            
            # 获取目录结构
            directory_structure = self._get_directory_structure(extracted_files_path)
            
            print(f"directory_structure:\n{directory_structure}")

            prompt = PROMPT.format(
                binary_filename = binary_filename,
                directory=directory_structure,
                cve_details=cve_details
            )

            enc = tiktoken.get_encoding("cl100k_base")
            enc = tiktoken.encoding_for_model("gpt-4o")
            token_ids = enc.encode(prompt)
            print(f"Prompt token 数: {len(token_ids)}")

            response = self.chat_model.chat(prompt)
            # print(f"大模型原始返回结果：{response}")

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