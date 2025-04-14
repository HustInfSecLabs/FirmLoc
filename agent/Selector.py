from agent.base import Agent
from model.base import ChatModel
from log import logger

PROMPT = """
...
{userinput}
...
"""

class Selector(Agent):

    def __init__(self, chat_model: ChatModel) -> None:
        super().__init__(chat_model)
        self.chat_model = chat_model

    def process(self, query: str) -> str:
        logger.info(f"Processing query: {query}")
        prompt = PROMPT.format(userinput=query)
        response = self.chat_model.chat(prompt)
        logger.info(f"Response: {response}")
        return response