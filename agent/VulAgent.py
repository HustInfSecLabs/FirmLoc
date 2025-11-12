import asyncio
import os
import time
import json
import ast
import asyncio
from fastapi import WebSocket
from pathlib import Path
from typing import Optional, Set

from model import ChatModel, AgentModel
from agent import UserAgent, PlannerAgent, ida
from state import ProgressEnum
from agent.bindiff_agent import BindiffAgent
from agent.ida_toolkits import IdaToolkit
from agent.binwalk import BinwalkAgent
from agent.online_search import OnlineSearchAgent
from agent.llm_diff import main as llm_diff
from agent.binary_filter import BinaryFilterAgent
from log import logger
from utils import ConfigManager, PlanManager
from utils.utils import get_firmware_files, copy_file, is_binary_file
from config import config_manager as config



class VulnAgent:
    def __init__(
        self,
        chat_id: str,
        user_input: str,
        websocket: WebSocket,
        cve_id: Optional[str] = None,
        binary_filename: Optional[str] = None,
        user_model: ChatModel = AgentModel("DeepSeek"),
        planner_model: ChatModel = AgentModel("DeepSeek"),
        config_dir: str = './history'
    ):
        self.user_model = user_model
        self.planner_model = planner_model
        self.config_dir = config_dir
        self.chat_id = str(chat_id)
        self.user_input = user_input
        self.websocket = websocket
        self.cve_id = cve_id
        self.binary_filename = binary_filename
        
        self.is_last = False
        self.agent = None
        self.tool_status = "stop"
        self.tool = None
        self.command = None
        self.tool_result = None

        self.files = get_firmware_files(f"{self.config_dir}/{self.chat_id}")

        self._init_bot()

    def _init_bot(self):
        self.user_agent = UserAgent(self.user_model)
        self.planner_agent = PlannerAgent(self.planner_model)
        self.online_search_agent = OnlineSearchAgent(self.user_model)
        self.BinwalkAgent = BinwalkAgent(self.planner_model)
        self.BinaryFilterAgent = BinaryFilterAgent(self.planner_model)
        self.IDAAgent = IdaToolkit()
        self.BindiffAgent = BindiffAgent(self.chat_id)
        
        self.config_manager = ConfigManager(
            chat_id=self.chat_id,
            user_id=123456,
            user_name="root",
            query=self.user_input,
            upload_files=self.files,
            config_path=self.config_dir
        )
        self.plan_manager = None
        #self.chat_id = None
        self.tasks = None
        self.results = None
        self.state = ProgressEnum.NOT_STARTED
    

    def on_status_update(self, command=None, tool=None, tool_status=None, tool_result=None):
        if command is not None:
            self.command = command
        if tool is not None:
            self.tool = tool
        if tool_status is not None:
            self.tool_status = tool_status
        if tool_result is not None:
            self.tool_result = tool_result

    async def send_message(self, content: str, message_type="message", tool_type=None, tool_content=None, agent=None, tool=None, tool_status=None):
        """
        发送消息到 WebSocket
        """
        system_status = {
            "status": self.state.name,
            "agent": agent,
            "tool": tool
        }

        # tool_status = None
        if tool:
            tool_status = {
                "type": tool_type,
                "title": tool_status,
                "content": tool_content
            }

        response = {
            "chat_id": self.chat_id,
            "is_last": self.is_last,
            "type": message_type,
            "content": content,
            "system_status": system_status,
            "tool_status": tool_status
        }

        try:
            await self.websocket.send_json(response)
            logger.info(f"发送消息: {response}")
        except Exception as e:
            logger.error(f"发送消息失败: {str(e)}")

    async def chat(self):
        """
        聊天接口
        :param chat_id: 会话ID
        :param query: 用户查询内容
        :return: 聊天响应
        """

        if not self.cve_id or not self.binary_filename:
            error_msg = "缺少CVE编号或目标二进制文件名称，无法继续执行分析。"
            await self.send_message(error_msg, message_type="message")
            logger.error(error_msg)
            return error_msg

        def show_file_info(full_path: str):
            """
            给定目录路径和文件名，打印文件的完整路径以及文件大小。
            """
            
            # 检查文件是否存在
            if not os.path.isfile(full_path):
                print(f"[错误] 文件不存在：{full_path}")
                return
            
            # 获取文件大小（字节）
            size_bytes = os.path.getsize(full_path)
            
            print(f"文件路径：{full_path}")
            print(f"文件大小：{size_bytes} 字节")

        if len(self.files) != 2:
            error_msg = "请上传两个固件文件以进行比较分析。"
            await self.send_message(error_msg, message_type="message")
            logger.error(error_msg)
            return error_msg
        self.tasks = """
## 1.使用Binwalk提取固件文件
## 2.筛选出可能存在漏洞的二进制文件
## 3.使用IDA导出两个不同版本二进制文件的.Binexport文件
## 4.使用BinDiff分析两个.export文件的差异
## 5.分析BinDiff的结果，找出可能存在漏洞的函数
## 6.使用IDA导出函数的伪C代码
## 7.使用Detection Agent分析函数的伪C代码
        """
        logger.info(f"Tasks: {self.tasks}")

        self.plan_manager = PlanManager(
            chat_id=self.chat_id,
            plan_path=self.config_dir,
            query=self.user_input,
            upload_files=self.files,
            plan=self.tasks
        )

        self.config_manager.update_agent_status(new_running_agent="Intelligence Agent")
        self.agent = "Intelligence Agent"
        self.tool = None
        self.state = ProgressEnum.RUNNING
        await self.send_message("情报收集智能体收集CVE相关信息",
                                 message_type="header1",
                                agent=self.agent,)
        search_result = self.online_search_agent.process(task_id=self.chat_id, cve_id=self.cve_id)
        logger.info(f"Online search result: {search_result}")

        with open(search_result['search_result_path'], 'r', encoding='utf-8') as f:
            tool_content = [
                {
                    "type": "text",
                    "content": f"{f.read()}"
                }
            ]
            await self.send_message(f"调用在线搜索API访问https://services.nvd.nist.gov",
                                        message_type="command",
                                        tool_type="graphics",
                                        tool_content=tool_content,
                                        agent=self.agent,
                                        tool="Online Search",
                                        tool_status="running")

        self.config_manager.update_agent_status("Intelligence Agent", "Binwalk Agent")
        self.agent = "Binwalk Agent"
        self.tool = None
        await self.send_message("Binwalk Agent提取固件文件",
                                message_type="header1",
                                agent=self.agent) 
        files = self.files
        
        binwalk_results = []

        for file in files:
            binwalk_result = await self.BinwalkAgent.process(
                task_id=self.chat_id,
                firmware_path=str(file),
                config=self.config_manager,
                send_message=self.send_message,
                on_status_update=self.on_status_update)
            print(binwalk_result)
            logger.info(f"Binwalk result: {binwalk_result}")
            binwalk_results.append(binwalk_result)

        cve_details = ""
        cwe = ""
        with open(search_result['search_result_path'], 'r', encoding='utf-8') as f:
            content = f.read()
            content = json.loads(content)
            cve_details = json.dumps(content['vulnerabilities'][0]['cve']['descriptions'][0]["value"])
            cwe = json.dumps(content['vulnerabilities'][0]['cve']['weaknesses'][0]["description"][0]['value'])

        print(f"cve_details: {cve_details}")
        self.config_manager.update_agent_status("Binwalk Agent", "Binary Filter Agent")
        self.config_manager.update_tool_status("Binwalk", "Binary Filter")

        self.agent = "Binwalk Agent"
        await self.send_message("Binary Filter Agent筛选可疑文件列表",
                                 message_type="header1",
                                agent=self.agent)
        llm_result = self.BinaryFilterAgent.process(
            binary_filename=self.binary_filename,
            extracted_files_path=binwalk_results[0]['extracted_files_path'],
            cve_details=cve_details
        )
        # llm_result = ast.literal_eval(config.config["LLM_RESULT"]["llm_result"])
        print(f"LLM result: {llm_result}")
        logger.info(f"LLM result: {llm_result}")


        suspicious_files = [os.path.join(name['binary_path']) for name in llm_result["suspicious_binaries"]]
        # suspicious_files = ['alphapd']
        print(f"可疑文件列表: {suspicious_files}")
        self.tool = None
        formatted_lines = [f"{i+1}. {path}" for i, path in enumerate(suspicious_files)]

        suspicious_lines = '\n'.join(formatted_lines)
        await self.send_message(f"可疑文件: {suspicious_lines}",
                                    message_type="message",
                                    agent=self.agent)
        idadir = os.path.join(self.config_dir, self.chat_id, "ida")
        bindiffdir = os.path.join(self.config_dir, self.chat_id, "bindiff")
        for file in suspicious_files:
            file1 = os.path.join(binwalk_results[0]['extracted_files_path'], file) 
            file2 = os.path.join(binwalk_results[1]['extracted_files_path'], file)
            # file1 = os.path.join('history', self.chat_id, 'alphapd14') 
            # file2 = os.path.join('history', self.chat_id, 'alphapd16')
            # 检查文件是否存在
            if not os.path.isfile(file1):
                print(f"文件不存在: {file1}")
                continue
            if not os.path.isfile(file2):
                print(f"文件不存在: {file2}")
                continue
            # 检查是否为二进制文件
            if not is_binary_file(file1) or not is_binary_file(file2):
                self.agent = None
                await self.send_message(f"文件 {file1} 不是二进制文件，跳过分析。",
                                        message_type="header2",
                                        agent=self.agent)
                continue

            os.makedirs(idadir, exist_ok=True)
            output_path1 = os.path.join(idadir, f"{os.path.basename(file1)}")
            output_path2 = os.path.join(idadir, f"{os.path.basename(file2)}1")
            show_file_info(file1)
            show_file_info(file2)
            file2 = copy_file(file2, os.path.dirname(file2))


            self.config_manager.update_agent_status("Binwalk Agent", "IDA Agent")
            self.config_manager.update_tool_status("Binwalk", "IDA Decompiler")
            self.tool = "IDA Decompiler"
            self.tool_status = "running"
            self.agent = "IDA Agent"
            self.tool = None
            # self.command = f"ida -o {output_file1} {file1}"
            await self.send_message(f"IDA Agent分析二进制文件{file.split('./', 1)[-1]}",
                                    message_type="header1",
                                agent=self.agent) 

            ida_service_url = config.config["IDA_SERVICE"]["service_url"]
            await ida.ida_process(input_file_path=file1, output_dir=output_path1, ida_service_url=ida_service_url, ida_version="ida64", config=self.config_manager, send_message=self.send_message, on_status_update=self.on_status_update)
            await ida.ida_process(input_file_path=file2, output_dir=output_path2, ida_service_url=ida_service_url, ida_version="ida64", config=self.config_manager, send_message=self.send_message, on_status_update=self.on_status_update)
            output_file1 = os.path.join("test", f"{os.path.basename(file1)}.BinExport")
            output_file2 = os.path.join("test", f"{os.path.basename(file2)}.BinExport")
            output_dir = os.path.join(bindiffdir, f"{os.path.basename(file1)}")


            self.config_manager.update_agent_status("IDA Agent", "Bindiff Agent")
            self.config_manager.update_tool_status("IDA Decompiler", "Bindiff")
            self.tool = "Bindiff"
            self.tool_status = "running"
            self.agent = "Bindiff Agent"
            self.tool = None
            await self.send_message("Bindiff Agent对比两个二进制文件",
                                    message_type="header1",
                                agent=self.agent) 

            bindiff_result = await self.BindiffAgent.execute(output_file1, output_file2, output_dir, self.config_manager, send_message=self.send_message, on_status_update=self.on_status_update)
            print(bindiff_result)

            self.agent = "Detection Agent"
            self.tool = None
            self.config_manager.update_agent_status("Bindiff Agent", "Detection Agent")
            await self.send_message("Detection Agent分析Bindiff结果",
                                    message_type="header1",
                                agent=self.agent)
            await llm_diff(
                chat_id=self.chat_id,
                history_root=self.config_dir,
                pre_c=os.path.join(output_path1,f"{os.path.basename(file1)}_pseudo.c"),
                post_c=os.path.join(output_path2,f"{os.path.basename(file2)}_pseudo.c"),
                binary_filename = os.path.basename(file1),
                cve_details=cve_details,
                cwe=cwe,
                send_message=self.send_message
            ) 
        
        self.is_last = True
        self.state = ProgressEnum.COMPLETED
        response = ""
        self.agent = None
        self.tool = None
        self.config_manager.update_agent_status(new_running_agent=None)
        self.config_manager.update_tool_status(new_running_tool=None)
        await self.send_message("系统运行完成。感谢使用 VulnAgent！",
                                 message_type="message")
        logger.info("系统运行完成")

        return response

