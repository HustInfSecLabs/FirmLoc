from model import ChatModel, QwenChatModel
from agent import UserAgent, PlannerAgent, Selector
from state import ProgressEnum

from log import logger


class VulnAgent:
    def __init__(self, user_model = QwenChatModel(), planner_model = QwenChatModel()):
        self.user_model = user_model
        self.planner_model = planner_model

        self._init_bot()

    def _init_bot(self):
        self.user_agent = UserAgent(self.user_model)
        self.planner_agent = PlannerAgent(self.planner_model)
        self.selector = Selector(self.user_model)

        self.chat_id = None
        self.user_input = ""
        self.tasks = ""
        self.results = ""
        self.state = ProgressEnum.NOT_STARTED

    def run(self, user_input: str):
        while True:
            self.state = ProgressEnum.USER_AGENT
            self.user_input = user_input
            self.tasks = self.user_agent.process(self.user_input)
            logger.info(f"Tasks: {self.tasks}")

            self.state = ProgressEnum.PLANNER_AGENT
            self.tasks = self.planner_agent.process(self.tasks, self.results)
            logger.info(f"Results: {self.results}")
            
            self.state = self.selector.process(self.tasks)
            
            pass

