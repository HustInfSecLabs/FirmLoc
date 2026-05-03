from agent.base import Agent
from model.base import ChatModel
from log import logger

PROMPT = """你是一个漏洞分析任务调度助手。

你需要根据用户输入的分析需求，判断应该使用哪种工具（ida, binwalk, bindiff），并输出结构化 JSON 格式的分析任务参数。
请根据用户输入，判断是否需要执行 bindiff 工具。
如果需要，请提取文件路径，并输出如下格式的 JSON：
{{
  "tool": "bindiff",
  "primary_export": "A文件路径",
  "secondary_export": "B文件路径",
  "task_name": "diff_analysis"
}}
如果用户输入内容与分析任务无关，请返回 {{"tool": "none"}}

请参考以下格式：

[用户输入]
请对A文件和B文件进行 bindiff 分析。

[结构化输出]
{{
  "tool": "bindiff",
  "primary_export": "A文件路径",
  "secondary_export": "B文件路径",
  "task_name": "diff_analysis"
}}


[用户输入]
{userinput}

[结构化输出]
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