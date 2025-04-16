from model import ChatModel, QwenChatModel
from agent import UserAgent, PlannerAgent, Selector
from state import ProgressEnum
from agent.bindiff_agent import BindiffAgent
from log import logger
import uuid
import json
import re

class VulnAgent:
    def __init__(self, user_model = QwenChatModel(), planner_model = QwenChatModel()):
        self.user_model = user_model
        self.planner_model = planner_model

        self._init_bot()

    def _init_bot(self):
        self.user_agent = UserAgent(self.user_model)
        self.planner_agent = PlannerAgent(self.planner_model)
        self.selector = Selector(self.user_model)
        self.chat_id = f"chat-{uuid.uuid4().hex[:8]}"


        #self.chat_id = None
        self.user_input = ""
        self.tasks = ""
        self.results = ""
        self.state = ProgressEnum.NOT_STARTED
        

    def run(self, user_input: str):
        self.user_input = user_input
        self.results = ""

        self.state = ProgressEnum.USER_AGENT
        self.user_input = user_input
        self.tasks = self.user_agent.process(self.user_input)
        logger.info(f"Tasks: {self.tasks}")

        self.state = ProgressEnum.PLANNER_AGENT
        self.tasks = self.planner_agent.process(self.tasks, self.results)
        logger.info(f"Results: {self.results}")
        
        selector_output = self.selector.process(self.user_input)
        logger.info(f"[Selector输出] {selector_output}")
        
        try:
            print("Selector 原始返回：\n", selector_output)
            match = re.search(r"\{[\s\S]*\}", selector_output)
            if not match:
                raise ValueError("未能提取有效 JSON 块")

            json_str = match.group()
            params = json.loads(json_str)

            tool_name = params.get("tool", "").lower()

            if tool_name == "bindiff":
                self.state = ProgressEnum.BINDIFFAGENT

                bindiff = BindiffAgent(
                    chat_id=self.chat_id,
                    task_name=params.get("task_name", "bindiff_task")
                )
                result = bindiff.execute(
                    primary_export=params["primary_export"],
                    secondary_export=params["secondary_export"]
                )

                stdout_text = result["result"].get("stdout", "").strip()

                self.results += (
                    f"\nBindiff 执行成功\n"
                    f"任务状态：{result['status']}\n"
                    f"输出目录：{result['result'].get('output_dir')}\n"
                    f"标准输出：\n{stdout_text}\n"
                )
                print("已完成 Bindiff 执行。")
                print("Bindiff 执行结果如下：")
                print(self.results)

            elif tool_name == "none":
                # fallback 到大模型助手回答模式
                response = self.user_model.chat(self.user_input)
                print("大模型回答：", response)
                self.results += f"\n普通问答模式回答：\n{response}\n"
                return

            else:
                print(f"当前不支持的工具类型：{tool_name}")

        except json.JSONDecodeError:
            print("无法解析大模型返回的结构化结果，请检查输出格式。")


if __name__ == "__main__":
    agent = VulnAgent()
    while True:
        user_input = input("请输入漏洞分析请求（输入 exit 退出）：\n> ")
        if user_input.lower() in {"exit", "quit"}:
            print("再见！")
            break

        agent.run(user_input)
        