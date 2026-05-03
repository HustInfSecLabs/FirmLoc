import os
import configparser
from typing import Optional, List


class Config:

    def __init__(self, config_path: str = None) -> None:
        if config_path:
            self.config_path = config_path
        else:
            self.config_path = os.path.join(os.path.dirname(__file__), "config.ini")

        self.read_config()

    def read_config(self):

        if self.config_path is None:
            raise AssertionError("config path is None, please give config path first")

        self.config = configparser.ConfigParser()
        try:
            self.config.read(self.config_path, encoding="utf-8")
        except UnicodeDecodeError:
            self.config.read(self.config_path, encoding="utf-8-sig")

    def get_llm_keys(self) -> List[str]:
        keys: List[str] = []
        for section in self.config.sections():
            if not section.startswith("LLM."):
                continue
            key = section.split("LLM.", 1)[1].strip()
            if key:
                keys.append(key)
        return keys

    def resolve_llm_key(self, preferred: Optional[str] = None, env_var: str = "VULN_LLM_MODEL_KEY") -> str:
        available = self.get_llm_keys()
        if not available:
            raise KeyError("No LLM.* sections found in config.ini")

        if preferred and preferred in available:
            return preferred

        ini_default = self.config.get("LLM", "default_key", fallback="").strip()
        if ini_default and ini_default in available:
            return ini_default

        env_value = (os.environ.get(env_var) or "").strip()
        if env_value and env_value in available:
            return env_value

        for candidate in ("GPT", "DeepSeek", "Claude"):
            if candidate in available:
                return candidate

        return available[0]


config_manager = Config()

