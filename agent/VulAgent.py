import asyncio
from fastapi import WebSocket

from model import ChatModel, QwenChatModel
from agent import UserAgent, PlannerAgent
from state import ProgressEnum
from agent.bindiff_agent import BindiffAgent
from agent.ida_toolkits import IdaToolkit
from log import logger
from utils import ConfigManager, PlanManager


class VulnAgent:
    def __init__(self, chat_id: str, user_input: str, websocket: WebSocket, user_model: ChatModel = QwenChatModel(), planner_model: ChatModel = QwenChatModel(), config_dir: str = './history'):
        self.user_model = user_model
        self.planner_model = planner_model
        self.config_dir = config_dir
        self.chat_id = chat_id
        self.user_input = user_input
        self.websocket = websocket
        
        self.is_last = False
        self.agent = None
        self.tool_status = "stop"
        self.tool = None
        self.command = None
        self.tool_result = None

        self._init_bot()

    def _init_bot(self):
        self.user_agent = UserAgent(self.user_model)
        self.planner_agent = PlannerAgent(self.planner_model)
        # self.selector = Selector(self.user_model)
        self.IDAAgent = IdaToolkit()
        self.BindiffAgent = BindiffAgent(self.chat_id)
        self.config_manager = ConfigManager(
            chat_id=self.chat_id,
            user_id=123456,
            user_name="root",
            query=self.user_input,
            upload_files="/home/wzh/Desktop/stack_overflow_demo, /home/wzh/Desktop/stack_overflow_demo_v1",
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
        :
        """
        system_status = {
            "status": self.state.name,
            "agent": self.agent,
            "tool": self.tool
        }

        if self.tool:
            tool_status = {
                "type": "terminal",
                "content": [
                    {
                        "user": "root@ubuntu:~$",
                        "input": self.command,
                        "output": self.tool_result
                    }
                ]
            }
        else:
            tool_status = None

        response = {
            "chat_id": self.chat_id,
            "is_last": self.is_last,
            "type": "message",
            "content": content,
            "system_status": system_status,
            "tool_status": tool_status
        }

        await self.websocket.send_json(response)
        logger.info(f"发送消息: {response}")

    async def chat(self):
        """
        聊天接口
        :param chat_id: 会话ID
        :param query: 用户查询内容
        :return: 聊天响应
        """
        # self.tasks = self.user_agent.process(query)
        # logger.info(f"Tasks: {self.tasks}")
        self.tasks = """
        ## 1.使用IDA分析文件，并导出.export文件
        ## 2.使用BinDiff分析两个.export文件的差异
        """
        logger.info(f"Tasks: {self.tasks}")

        self.planner_manager = PlanManager(
            chat_id=self.chat_id,
            plan_path=self.config_dir,
            query=self.user_input,
            upload_files="/home/wzh/Desktop/stack_overflow_demo, /home/wzh/Desktop/stack_overflow_demo_v1",
            plan=self.tasks
        )

        self.config_manager.update_agent_status(new_running_agent="Binwalk Agent")
        self.config_manager.update_tool_status(new_running_tool="Binwalk")
        self.tool = "Binwalk"
        self.tool_status = "running"
        self.agent = "Binwalk Agent"
        self.command = "binwalk -e /home/wzh/Desktop/stack_overflow_demo"
        await self.send_message("正在运行 Binwalk...")
        await asyncio.sleep(5)  # 模拟处理间隔


        file1 = "/home/wzh/Desktop/stack_overflow_demo"
        output_file1 = "/home/wzh/Desktop/Project/VulnAgent/save/stack_overflow_demo.export"
        file2 = "/home/wzh/Desktop/stack_overflow_demo_v1"
        output_file2 = "/home/wzh/Desktop/Project/VulnAgent/save/stack_overflow_demo_v1.export"

        # result1 = self.IDAAgent.analyze_binary(file1, output_file1)
        # result2 = self.IDAAgent.analyze_binary(file2, output_file2)

        self.config_manager.update_agent_status("Binwalk Agent", "IDA Agent")
        self.config_manager.update_tool_status("Binwalk", "IDA Decompiler")
        self.tool = "IDA Decompiler"
        self.tool_status = "running"
        self.agent = "IDA Agent"
        self.command = f"ida -o {output_file1} {file1}"
        # self.tool_result = result1 + "\n" + result2
        await self.send_message("正在运行 IDA Decompiler...")
        await asyncio.sleep(5)

        bindiff_result = self.BindiffAgent.execute(output_file1, output_file2)
        print(bindiff_result)

        self.config_manager.update_agent_status("IDA Agent", "Bindiff Agent")
        self.config_manager.update_tool_status("IDA Decompiler", "Bindiff")
        self.tool = "Bindiff"
        self.tool_status = "running"
        self.agent = "Bindiff Agent"
        self.command = f"bindiff -o {bindiff_result['result'].get('output_dir')} {output_file1} {output_file2}"
        self.tool_result = bindiff_result["result"].get("stdout", "").strip()
        await self.send_message("正在运行 Bindiff...")
        await asyncio.sleep(5)



        self.config_manager.update_agent_status("Bindiff Agent", "Detection Agent")
        self.config_manager.update_tool_status("Bindiff")
        self.plan_manager.add_plan("## 3.使用Detection Agent分析文件")
        self.plan_manager.add_result(bindiff_result)
        self.agent = "Detection Agent"
        self.tool = None
        self.tool_status = "stop"
        await self.send_message("正在运行 Detection Agent...")
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
        