from model import ChatModel, QwenChatModel
from agent import UserAgent, PlannerAgent, Selector
from state import ProgressEnum
from agent.bindiff_agent import BindiffAgent
from log import logger
import uuid
import json
import re
import configparser
from pathlib import Path

class VulnAgent:
    def __init__(self, user_model: ChatModel = QwenChatModel(), planner_model: ChatModel = QwenChatModel(), config_dir: str = './save'):
        self.user_model = user_model
        self.planner_model = planner_model
        self.config_dir = config_dir

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

    def generate_chat_config(self, chat_id: str, user_id: int, user_name: str, query: str):
        """
        生成会话配置文件
        :param chat_id: 会话ID
        :param user_id: 用户ID
        :param user_name: 用户名
        :param query: 用户查询内容
        """
        config = configparser.ConfigParser()
        
        # 生成 chat 配置节
        config["chat"] = {
            "chat_id": chat_id,
            "user_id": str(user_id),
            "user_name": user_name,
            "#": "会话基础信息"
        }
        
        # 日志配置
        config["log"] = {
            "file_path": "vulnagent.log",
            "#": "日志文件路径"
        }
        
        # 大模型配置
        config["llm"] = {
            "model_name": "gpt-4o-mini",
            "temperature": "1",
            "#": "大模型参数"
        }
        
        # 任务规划配置
        config["plan"] = {
            "query": query,
            "upload_files": "",
            "file_path": "plan.md",
            "#": "任务规划信息"
        }
        
        # 智能体配置
        config["agent"] = {
            "running_agent": "",
            "unrunning_agent": "Binwalk Agent, IDA Agent, Bindiff Agent, Detection Agent, Location Agent",
            "completed_agent": "",
            "#": "智能体状态"
        }
        
        # 工具配置
        config["tool"] = {
            "running_tool": "",
            "unrunning_tool": "Binwalk, IDA Decompiler, Bindiff",
            "completed_tool": "",
            "#": "工具状态"
        }
        
        # 创建配置目录
        config_dir = Path(self.config_dir) / chat_id
        config_dir.mkdir(parents=True, exist_ok=True)
        
        # 写入配置文件
        config_path = config_dir / "config.ini"
        with open(config_path, "w", encoding="utf-8") as f:
            config.write(f)
            
        return str(config_path)
    def update_config_value(self, chat_id: str, section: str, key: str, value: str):
        """
        更新配置文件字段
        :param chat_id: 会话ID
        :param section: 配置节名称
        :param key: 字段名称
        :param value: 要更新的值
        """
        config_path = Path(self.config_dir) / chat_id / "config.ini"
        if not config_path.exists():
            raise FileNotFoundError(f"配置文件不存在: {config_path}")
        
        config = configparser.ConfigParser()
        config.read(config_path)
        
        if not config.has_section(section):
            raise ValueError(f"配置节不存在: {section}")
        
        config.set(section, key, value)
        
        with open(config_path, "w", encoding="utf-8") as f:
            config.write(f)

if __name__ == "__main__":
    agent = VulnAgent()
    while True:
        user_input = input("请输入漏洞分析请求（输入 exit 退出）：\n> ")
        if user_input.lower() in {"exit", "quit"}:
            print("再见！")
            break

        agent.run(user_input)
        