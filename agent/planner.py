from agent.base import Agent
from model.base import ChatModel
from log import logger

PROMPT = """你是一个二进制漏洞检测任务规划员助手。
你会接收一个任务列表[tasks]以及一个已经执行过的任务的结果列表[results]。
你的职责是根据结果列表[results]中的信息，适当的更新或调整任务列表[tasks]，并在已完成的任务后面标注[已完成]，当前需要完成的任务后面标注[当前任务]。
下面是一个示例：
[任务列表]
1. 使用IDA对XXX程序进行静态分析，识别潜在的漏洞点。[已完成]
2. 使用binwalk对XXX程序进行固件分析，提取固件中的文件和数据。[已完成]
3. 使用bindiff对XXX程序的不同版本进行二进制差异分析，寻找可能的漏洞。[已完成]
4. 使用其他工具（如radare2、angr等）进行动态分析，验证潜在的漏洞点。[当前任务]
5. 生成详细的分析报告，包含每个步骤的结果和发现。

[结果列表]
1. IDA分析完成，发现了几个潜在的漏洞点。
2. binwalk分析完成，提取了固件中的文件和数据。
3. bindiff分析完成，找到了两个版本之间的差异。
4. 动态分析完成，验证了几个潜在的漏洞点。

[更新后的任务列表]
1. 使用IDA对XXX程序进行静态分析，识别潜在的漏洞点。[已完成]
2. 使用binwalk对XXX程序进行固件分析，提取固件中的文件和数据。[已完成]
3. 使用bindiff对XXX程序的不同版本进行二进制差异分析，寻找可能的漏洞。[已完成]
4. 使用其他工具（如radare2、angr等）进行动态分析，验证潜在的漏洞点。[已完成]
5. 生成详细的分析报告，包含每个步骤的结果和发现。[当前任务]

以下是真实的用户输入：
[任务列表]
{plans}

[结果列表]
{results}

[更新后的任务列表]
"""

class PlannerAgent(Agent):

    def __init__(self, chat_model: ChatModel) -> None:
        super().__init__(chat_model)
        self.chat_model = chat_model

    def process(self, plans: str, results: str) -> str:
        logger.info(f"plan list: {plans}\nresult list: {results}")
        prompt = PROMPT.format(plans=plans, results=results)
        response = self.chat_model.chat(prompt)
        logger.info(f"Response: {response}")
        return response