import asyncio
import os
import re
import json
from fastapi import WebSocket
from pathlib import Path
from typing import Set

from model import ChatModel, QwenChatModel, AgentModel
from agent import UserAgent, PlannerAgent
from state import ProgressEnum
from agent.bindiff_agent import BindiffAgent
from agent.ida_toolkits import IdaToolkit
from agent.binwalk import BinwalkAgent
from agent.online_search import OnlineSearchAgent
from agent.llm_diff import main as llm_diff
from agent.binary_filter import BinaryFilterAgent
from log import logger
from utils import ConfigManager, PlanManager
from utils.utils import get_firmware_files, copy_file



class VulnAgent:
    def __init__(self, chat_id: str, user_input: str, websocket: WebSocket, user_model: ChatModel = AgentModel("GPT"), planner_model: ChatModel = AgentModel("GPT"), config_dir: str = './history'):
        self.user_model = user_model
        self.planner_model = planner_model
        self.config_dir = config_dir
        self.chat_id = str(chat_id)
        self.user_input = user_input
        self.websocket = websocket
        
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
        # self.selector = Selector(self.user_model)
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
    
    async def send_message(self, content: str):
        """
        发送消息到 WebSocket
        """
        system_status = {
            "status": self.state.name,
            "agent": self.agent,
            "tool": self.tool
        }

        tool_status = None
        if self.tool:
            tool_status = {
                "type": "terminal",
                "content": [
                    {
                        "user": "root@ubuntu:~$",
                        "input": self.command or "",
                        "output": self.tool_result or ""
                    }
                ]
            }

        response = {
            "chat_id": self.chat_id,
            "is_last": self.is_last,
            "type": "message",
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
        # self.tasks = self.user_agent.process(query)
        # logger.info(f"Tasks: {self.tasks}")
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

        self.tasks = """
        ## 1.使用Binwalk提取固件文件
        ## 2.筛选出可能存在漏洞的二进制文件
        ## 3.使用IDA导出两个不同版本二进制文件的.export文件
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

        self.config_manager.update_agent_status(new_running_agent="Online Search Agent")
        self.config_manager.update_tool_status(new_running_tool="Online Search")
        self.tool = "Online Search"
        self.tool_status = "running"
        self.agent = "Online Search Agent"
        await self.send_message("正在运行 Online Search Agent...")
        await asyncio.sleep(0) 
        search_result = self.online_search_agent.process(task_id=self.chat_id, cve_id="CVE-2019-20760") # CVE-2019-20760 CVE-2021-20090 CVE-2024-39226
        logger.info(f"Online search result: {search_result}")
        

        self.config_manager.update_agent_status("Online Search Agent", "Binwalk Agent")
        self.config_manager.update_tool_status("Online Search", new_running_tool="Binwalk")
        self.tool = "Binwalk"
        self.tool_status = "running"
        self.agent = "Binwalk Agent"
        self.command = "binwalk -e ..."
        await self.send_message("正在运行 Binwalk...")
        await asyncio.sleep(0) 
        # await asyncio.sleep(10)  # 模拟处理间隔
        
        files = self.files
        
        binwalk_results = []

        for file in files:
            binwalk_result = self.BinwalkAgent.process(
                task_id=self.chat_id,
                firmware_path=str(file))
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
        llm_result = self.BinaryFilterAgent.process(
            # binary_filename="Buffalo WSR-2533DHPL2",
            binary_filename="Netgear R9000",
            # binary_filename="GL-iNet",
            # extracted_files_path=os.path.join(binwalk_results[0]['extracted_files_path'],"squashfs-root/usr/sbin/"),
            extracted_files_path=binwalk_results[0]['extracted_files_path'],
            cve_details=cve_details
        )
        print(f"LLM result: {llm_result}")
        logger.info(f"LLM result: {llm_result}")

        suspicious_files = [os.path.join(name['binary_path']) for name in llm_result["suspicious_binaries"]]

        # suspicious_files = [f"squashfs-root/usr/sbin/{name}" for name in matches]
        print(f"可疑文件: {suspicious_files}")
        idadir = os.path.join("/home/wzh/Desktop/Project/VulnAgent/history", self.chat_id, "ida")
        bindiffdir = os.path.join("/home/wzh/Desktop/Project/VulnAgent/history", self.chat_id, "bindiff")
        for file in suspicious_files:
            file1 = f"./{binwalk_results[0]['extracted_files_path']}/{file}"
            file2 = f"./{binwalk_results[1]['extracted_files_path']}/{file}" # 大模型回答与 路径有问题
            # 检查文件是否存在
            if not os.path.isfile(file1):
                print(f"文件不存在: {file1}")
                continue
            if not os.path.isfile(file2):
                print(f"文件不存在: {file2}")
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
            # self.command = f"ida -o {output_file1} {file1}"
            # self.tool_result = result1 + "\n" + result2
            await self.send_message("正在运行 IDA Decompiler...")
            await asyncio.sleep(0) 


            result1 = self.IDAAgent.analyze_binary(file1, output_path1, ida_version="ida32")
            result2 = self.IDAAgent.analyze_binary(file2, output_path2, ida_version="ida32")
            print(result1)
            print(result2)
            output_file1 = os.path.join("test", f"{os.path.basename(file1)}.BinExport")
            output_file2 = os.path.join("test", f"{os.path.basename(file2)}.BinExport")
            output_dir = os.path.join(bindiffdir, f"{os.path.basename(file1)}")


            self.config_manager.update_agent_status("IDA Agent", "Bindiff Agent")
            self.config_manager.update_tool_status("IDA Decompiler", "Bindiff")
            self.tool = "Bindiff"
            self.tool_status = "running"
            self.agent = "Bindiff Agent"
            await self.send_message("正在运行 Bindiff...")
            await asyncio.sleep(0) 

            bindiff_result = self.BindiffAgent.execute(output_file1, output_file2, output_dir)
            print(bindiff_result)
            llm_diff(
                chat_id=self.chat_id,
                history_root=self.config_dir,
                pre_c=os.path.join(output_path1,f"{os.path.basename(file1)}_pseudo.c"),
                post_c=os.path.join(output_path2,f"{os.path.basename(file2)}_pseudo.c"),
                binary_filename = os.path.basename(file1),
                cve_details=cve_details,
                cwe=cwe,
            )

        
        self.is_last = True
        self.state = ProgressEnum.COMPLETED
        response = ""

        return response

if __name__ == "__main__":
    agent = VulnAgent()
    while True:
        user_input = input("请输入漏洞分析请求（输入 exit 退出）：\n> ")
        if user_input.lower() in {"exit", "quit"}:
            print("再见！")
            break

        agent.run(user_input)
