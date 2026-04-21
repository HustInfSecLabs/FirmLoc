import configparser
import os
from pathlib import Path


class LLMRoutingConfigError(ValueError):
    pass


class Config:
    LLM_ROUTING_SECTION = "LLM_ROUTING"
    DEFAULT_MODEL_KEY = "default_model"
    ENV_CONFIG_PATH = "VULNAGENT_CONFIG"

    def __init__(self, config_path: str | None = None) -> None:
        if config_path:
            self.config_path = config_path
        else:
            env_config_path = os.environ.get(self.ENV_CONFIG_PATH)
            if env_config_path:
                self.config_path = str(Path(env_config_path).expanduser())
            else:
                self.config_path = os.path.join(os.path.dirname(__file__), "config.ini")

        self.read_config()

    def read_config(self):

        if self.config_path is None:
            raise AssertionError("config path is None, please give config path first")

        self.config = configparser.ConfigParser()
        self.config.read(self.config_path)

    def get_routed_model_alias(self, module_key: str) -> str:
        if not self.config.has_section(self.LLM_ROUTING_SECTION):
            raise LLMRoutingConfigError(f"missing config section: {self.LLM_ROUTING_SECTION}")

        routing_section = self.config[self.LLM_ROUTING_SECTION]
        model_alias = (routing_section.get(module_key) or "").strip()
        if not model_alias:
            model_alias = (routing_section.get(self.DEFAULT_MODEL_KEY) or "").strip()

        if not model_alias:
            raise LLMRoutingConfigError(
                f"missing {self.LLM_ROUTING_SECTION}.{self.DEFAULT_MODEL_KEY}"
            )

        section_name = f"LLM.{model_alias}"
        if not self.config.has_section(section_name):
            raise LLMRoutingConfigError(
                f"module '{module_key}' routes to unknown model alias '{model_alias}' "
                f"(expected section '{section_name}')"
            )

        return model_alias

    def get_llm_config_by_alias(self, model_alias: str) -> dict:
        normalized_alias = (model_alias or "").strip()
        section_name = f"LLM.{normalized_alias}"
        if not normalized_alias or not self.config.has_section(section_name):
            raise LLMRoutingConfigError(
                f"unknown model alias '{model_alias}' (expected section '{section_name}')"
            )

        model_name = (self.config[section_name].get("model_name") or "").strip()
        if not model_name:
            raise LLMRoutingConfigError(
                f"missing required field 'model_name' in section '{section_name}'"
            )

        return {
            "alias": normalized_alias,
            "section": section_name,
            "model_name": model_name,
            "api_key": self.config[section_name].get("api_key", ""),
            "base_url": self.config[section_name].get("base_url", ""),
        }

    def get_llm_config_for(self, module_key: str) -> dict:
        return self.get_llm_config_by_alias(self.get_routed_model_alias(module_key))

    def build_agent_model(self, module_key: str):
        from model.agentmodel import AgentModel

        return AgentModel(self.get_routed_model_alias(module_key))


config_manager = Config()
