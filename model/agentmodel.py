from model.base import ChatModel
from config import config_manager

from openai import OpenAI


class AgentModel(ChatModel):

    def __init__(self, model: str = None):
        super().__init__()
        api_key = config_manager.config["LLM." + model]["api_key"]
        base_url = config_manager.config["LLM." + model]["base_url"]
        self.model_name = config_manager.config["LLM." + model]["model_name"]
        self.client = OpenAI(api_key=api_key, base_url=base_url)

    def create_completion(self, messages: list, temperature: float = 0):
        return self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            temperature=temperature,
        )

    @staticmethod
    def extract_text(completion) -> str:
        return completion.choices[0].message.content

    @staticmethod
    def extract_usage(completion) -> dict:
        usage = getattr(completion, "usage", None)
        if usage is None:
            return {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        return {
            "prompt_tokens": int(getattr(usage, "prompt_tokens", 0) or 0),
            "completion_tokens": int(getattr(usage, "completion_tokens", 0) or 0),
            "total_tokens": int(getattr(usage, "total_tokens", 0) or 0),
        }

    def chat(self, prompt: str = None) -> str:
        completion = self.create_completion([
            {
                'role': 'system',
                'content': 'You are a helpful assistant.'
            }, {
                'role': 'user',
                'content': prompt,
            }
        ])
        return self.extract_text(completion)
