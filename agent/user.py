from agent.base import Agent
from model.base import ChatModel
from log import logger

PROMPT = """你是一个二进制漏洞领域的专家助手。
你掌握二进制漏洞挖掘的相关知识和IDA、binwalk、bindiff等工具的使用。
你的任务是根据用户的需求生成一个漏洞检测任务列表。

下面是一个示例：
[用户输入]
请帮我对XXX程序进行漏洞检测

[任务列表]
1. 使用IDA对XXX程序进行静态分析，识别潜在的漏洞点。
2. 使用binwalk对XXX程序进行固件分析，提取固件中的文件和数据。
3. 使用bindiff对XXX程序的不同版本进行二进制差异分析，寻找可能的漏洞。
4. 使用其他工具（如radare2、angr等）进行动态分析，验证潜在的漏洞点。
5. 生成详细的分析报告，包含每个步骤的结果和发现。

以下是真实的用户输入：
[用户输入]
{userinput}

[任务列表]
"""

class UserAgent(Agent):

    def __init__(self, chat_model: ChatModel) -> None:
        super().__init__(chat_model)
        self.chat_model = chat_model

    def process(self, query: str) -> str:
        logger.info(f"Processing query: {query}")
        prompt = PROMPT.format(userinput=query)
        response = self.chat_model.chat(prompt)
        logger.info(f"Response: {response}")
        return response
    
