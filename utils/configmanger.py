import configparser
from pathlib import Path
from typing import List, Dict

class ConfigManager:
    def __init__(self, chat_id: str, user_id: int, user_name: str, query: str, upload_files: str, config_path: str = "../save"):
        self.chat_id = chat_id
        self.config_path = Path(f"{config_path}/{chat_id}/config.ini")
        self.config = configparser.ConfigParser()
        self.user_id = user_id
        self.user_name = user_name
        self.query = query
        self.upload_files = upload_files

        # 初始化配置文件
        if not self.config_path.exists():
            self._init_config()
        else:
            self.config.read(self.config_path)

    def _init_config(self):
        """
        生成会话配置文件
        :param chat_id: 会话ID
        :param user_id: 用户ID
        :param user_name: 用户名
        :param query: 用户查询内容
        """
        # 生成 chat 配置节
        self.config["chat"] = {
            "chat_id": self.chat_id,
            "user_id": str(self.user_id),
            "user_name": self.user_name,
            "#": "会话基础信息"
        }
        
        # 日志配置
        self.config["log"] = {
            "file_path": "vulnagent.log",
            "#": "日志文件路径"
        }
        
        # 大模型配置
        self.config["llm"] = {
            "model_name": "gpt-4o-mini",
            "temperature": "1",
            "#": "大模型参数"
        }
        
        # 任务规划配置
        self.config["plan"] = {
            "query": self.query,
            "upload_files": self.upload_files,
            "file_path": "plan.md",
            "#": "任务规划信息"
        }
        
        self.config["agent"] = {
            "running_agent": "",
            "unrunning_agent": "Binwalk Agent, IDA Agent, Bindiff Agent, Detection Agent, Location Agent",
            "completed_agent": "",
            "#": "智能体运行状态"
        }
        self.config["tool"] = {
            "running_tool": "",
            "unrunning_tool": "Binwalk, IDA Decompiler, Bindiff",
            "completed_tool": "",
            "#": "工具运行状态"
        }
        self._save_config()

    def _save_config(self):
        """保存配置文件"""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, 'w') as f:
            self.config.write(f)

    def _parse_list(self, raw_str: str) -> List[str]:
        """字符串转列表"""
        return [a.strip() for a in raw_str.split(',') if a.strip()] if raw_str else []

    def _format_str(self, items: List[str]) -> str:
        """列表转字符串"""
        return ", ".join(items) if items else ""

    def update_agent_status(
        self,
        completed_agent: str = None,
        new_running_agent: str = None
    ):
        """
        更新智能体状态
        :param completed_agent: 刚完成运行的智能体
        :param new_running_agent: 新启动的智能体
        """
        # 获取当前状态
        running = self._parse_list(self.config["agent"]["running_agent"])
        unrun = self._parse_list(self.config["agent"]["unrunning_agent"])
        completed = self._parse_list(self.config["agent"]["completed_agent"])

        # 状态转移逻辑
        if completed_agent:
            if completed_agent in running:
                running.remove(completed_agent)
                completed.append(completed_agent)
        
        if new_running_agent:
            if new_running_agent in unrun:
                unrun.remove(new_running_agent)
                running.append(new_running_agent)

        # 更新配置
        self.config["agent"]["running_agent"] = self._format_str(running)
        self.config["agent"]["unrunning_agent"] = self._format_str(unrun)
        self.config["agent"]["completed_agent"] = self._format_str(completed)
        
        self._save_config()

    def update_tool_status(
        self,
        completed_tool: str = None,
        new_running_tool: str = None
    ):
        """
        更新工具状态
        :param completed_tool: 刚完成运行的工具
        :param new_running_tool: 新启动的工具
        """
        # 获取当前状态
        running = self._parse_list(self.config["tool"]["running_tool"])
        unrun = self._parse_list(self.config["tool"]["unrunning_tool"])
        completed = self._parse_list(self.config["tool"]["completed_tool"])

        # 状态转移逻辑
        if completed_tool:
            if completed_tool in running:
                running.remove(completed_tool)
                completed.append(completed_tool)

        if new_running_tool:
            if new_running_tool in unrun:
                unrun.remove(new_running_tool)
                running.append(new_running_tool)

        # 更新配置
        self.config["tool"]["running_tool"] = self._format_str(running)
        self.config["tool"]["unrunning_tool"] = self._format_str(unrun)
        self.config["tool"]["completed_tool"] = self._format_str(completed)
        
        self._save_config()
    