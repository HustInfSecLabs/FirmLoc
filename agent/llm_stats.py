import tiktoken

from log import logger


class LLMStats:
    def __init__(self):
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_calls = 0
        self.total_time = 0.0
        self.records = []
        self.model_totals = {}

    def add_record(self, prompt_tokens, completion_tokens, cost_time, tag="", model_name=""):
        self.total_prompt_tokens += prompt_tokens
        self.total_completion_tokens += completion_tokens
        self.total_calls += 1
        self.total_time += cost_time
        model_key = str(model_name or "Unknown")
        if model_key not in self.model_totals:
            self.model_totals[model_key] = {
                "calls": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "time": 0.0,
            }
        self.model_totals[model_key]["calls"] += 1
        self.model_totals[model_key]["prompt_tokens"] += prompt_tokens
        self.model_totals[model_key]["completion_tokens"] += completion_tokens
        self.model_totals[model_key]["time"] += cost_time
        self.records.append({
            "tag": tag,
            "model_name": model_key,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "time": round(cost_time, 4)
        })

    def summary(self):
        by_model = {}
        for model_name, stats in self.model_totals.items():
            by_model[model_name] = {
                "calls": stats["calls"],
                "prompt_tokens": stats["prompt_tokens"],
                "completion_tokens": stats["completion_tokens"],
                "total_tokens": stats["prompt_tokens"] + stats["completion_tokens"],
                "total_time_seconds": round(stats["time"], 4),
                "avg_time_per_call": round(stats["time"] / stats["calls"], 4) if stats["calls"] else 0,
            }
        return {
            "total_calls": self.total_calls,
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "total_tokens": self.total_prompt_tokens + self.total_completion_tokens,
            "total_time_seconds": round(self.total_time, 4),
            "avg_time_per_call": round(self.total_time / self.total_calls, 4) if self.total_calls else 0,
            "by_model": by_model,
        }


LLM_STATS = LLMStats()

MODEL_TO_ENCODING = {
    "deepseek-reasoner": "cl100k_base",
    "deepseek-chat": "cl100k_base",
}


def count_tokens(text: str, model_name: str = "gpt-4o") -> int:
    try:
        encoding_name = MODEL_TO_ENCODING.get(model_name)
        if encoding_name:
            enc = tiktoken.get_encoding(encoding_name)
        else:
            enc = tiktoken.encoding_for_model(model_name)
        return len(enc.encode(text))
    except Exception as e:
        logger.warning(f"Token计数失败，使用近似估算: {e}")
        return len(text) // 2
