# -*- coding: utf-8 -*-
"""
Vulnerability Analysis ReAct Agent

translated LangChain ReAct translated
"""
import os
import re
import json
import asyncio
import time
import functools
import io
import contextlib
from typing import Optional, Dict, Any, List, Callable
from pathlib import Path

from langchain.agents import AgentExecutor, create_react_agent
from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate
from langchain.memory import ConversationBufferWindowMemory
from langchain.callbacks.base import BaseCallbackHandler

from log import logger
from config import config_manager
from agent.llm_stats import LLM_STATS, count_tokens
from agent.vuln_tools import (
    VulnToolContext, 
    PseudoCodeIndex,
    create_vuln_tools,
    set_tool_context
)
from agent.prompts.vuln_react_prompts import (
    VULN_REACT_SYSTEM_PROMPT,
    VULN_REACT_HUMAN_PROMPT,
    format_few_shot_examples,
    format_cwe_repair_samples,
    ANALYSIS_OUTPUT_FORMAT,
    RAG_ENHANCED_PROMPT
)
from agent.llm_diff import (
    load_cwe_samples,
    select_cwe_samples,
    format_samples_for_prompt,
    gpt_inference
)

DEFAULT_LLM_CONFIG_KEY = config_manager.resolve_llm_key()


class ReasoningStreamHandler(BaseCallbackHandler):
    """
    translated
    
    translated Agent translated
    """
    
    def __init__(self, send_message: Optional[Callable] = None):
        """
        translated
        
        Args:
            send_message: translated,translated
        """
        self.send_message = send_message
        self.current_thought = ""
        self.step_count = 0
    
    def on_agent_action(self, action, **kwargs):
        """Agent translated"""
        self.step_count += 1
        message = f"🔧 Step {self.step_count}: Using tool `{action.tool}`\n"
        message += f"   Input: {action.tool_input}"
        
        logger.info(message)
        self._dispatch_message(message, "reasoning")
    
    def on_tool_end(self, output, **kwargs):
        """translated"""
        display_output = output[:300] + "..." if len(output) > 300 else output
        message = f"📋 Tool Output: {display_output}"
        
        logger.debug(message)
        self._dispatch_message(message, "tool_output")
    
    def on_agent_finish(self, finish, **kwargs):
        """Agent translated"""
        message = f"✅ Analysis Complete (Total steps: {self.step_count})"
        
        logger.info(message)
        self._dispatch_message(message, "complete")
    
    def on_llm_start(self, serialized, prompts, **kwargs):
        """LLM translated"""
        message = "🤔 Thinking..."
        self._dispatch_message(message, "thinking")

    def _dispatch_message(self, message: str, msg_type: str) -> None:
        """translated/translated"""
        if not self.send_message:
            return

        if asyncio.iscoroutinefunction(self.send_message):
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop and loop.is_running():
                loop.create_task(self._async_send(message, msg_type))
            else:
                asyncio.run(self._async_send(message, msg_type))
        else:
            try:
                self.send_message(message, message_type=msg_type)
            except Exception as e:
                logger.error(f"translated: {e}")
    
    async def _async_send(self, message: str, msg_type: str):
        """translated"""
        try:
            if asyncio.iscoroutinefunction(self.send_message):
                await self.send_message(message, message_type=msg_type)
            else:
                self.send_message(message, message_type=msg_type)
        except Exception as e:
            logger.error(f"translated: {e}")


class LLMUsageTracker(BaseCallbackHandler):
    """translated ReAct translated LLM translated usage."""

    def __init__(self):
        self.records: List[Dict[str, int]] = []

    def reset(self):
        self.records = []

    def on_llm_end(self, response, **kwargs):
        prompt_tokens = 0
        completion_tokens = 0

        llm_output = getattr(response, "llm_output", None) or {}
        token_usage = llm_output.get("token_usage") or {}
        if token_usage:
            prompt_tokens = int(token_usage.get("prompt_tokens", 0) or 0)
            completion_tokens = int(token_usage.get("completion_tokens", 0) or 0)
        else:
            generations = getattr(response, "generations", None) or []
            try:
                message = generations[0][0].message
                usage_metadata = getattr(message, "usage_metadata", None) or {}
                prompt_tokens = int(usage_metadata.get("input_tokens", 0) or 0)
                completion_tokens = int(usage_metadata.get("output_tokens", 0) or 0)
            except Exception:
                pass

        if prompt_tokens or completion_tokens:
            self.records.append({
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
            })


class SanitizedStreamWrapper:
    def __init__(self, stream: Any, recorder: "RawUsageRecorder"):
        self._stream = stream
        self._recorder = recorder

    def __enter__(self):
        self._stream.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        return self._stream.__exit__(exc_type, exc, tb)

    def __iter__(self):
        last_chunk = None
        for chunk in self._stream:
            last_chunk = chunk
            yield self._recorder._sanitize_chunk(chunk)
        if last_chunk is not None:
            self._recorder.capture_final_chunk(last_chunk)

    def __getattr__(self, name):
        return getattr(self._stream, name)


class SanitizedAsyncStreamWrapper:
    def __init__(self, stream: Any, recorder: "RawUsageRecorder"):
        self._stream = stream
        self._recorder = recorder

    async def __aenter__(self):
        await self._stream.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return await self._stream.__aexit__(exc_type, exc, tb)

    def __aiter__(self):
        return self

    async def __anext__(self):
        chunk = await self._stream.__anext__()
        self._recorder._last_async_chunk = chunk
        return self._recorder._sanitize_chunk(chunk)

    def __getattr__(self, name):
        return getattr(self._stream, name)


class RawUsageRecorder:
    """translated create() translated usage."""

    def __init__(self):
        self.records: List[Dict[str, int]] = []
        self.debug_samples: List[Dict[str, Any]] = []
        self.final_chunk_summary: Optional[Dict[str, Any]] = None
        self._last_async_chunk: Optional[Any] = None
        self._patched = False

    def reset(self):
        self.records = []
        self.debug_samples = []
        self.final_chunk_summary = None
        self._last_async_chunk = None

    def _safe_list_keys(self, value: Any) -> List[str]:
        if isinstance(value, dict):
            return sorted(str(k) for k in value.keys())[:20]
        return []

    def _summarize_response(self, response: Any) -> Dict[str, Any]:
        usage = getattr(response, "usage", None)
        summary: Dict[str, Any] = {
            "response_type": type(response).__name__,
            "has_usage_attr": hasattr(response, "usage"),
            "usage_present": usage is not None,
            "has_response_metadata": hasattr(response, "response_metadata"),
            "has_usage_metadata": hasattr(response, "usage_metadata"),
        }

        if usage is not None:
            summary["usage_type"] = type(usage).__name__
            usage_attrs = ("prompt_tokens", "completion_tokens", "total_tokens", "input_tokens", "output_tokens")
            summary["usage_attrs"] = [attr for attr in usage_attrs if hasattr(usage, attr)]
            summary["usage_values"] = {
                attr: getattr(usage, attr, None)
                for attr in usage_attrs
                if hasattr(usage, attr)
            }
            model_dump = getattr(usage, "model_dump", None)
            if callable(model_dump):
                try:
                    summary["usage_dump"] = model_dump()
                except Exception:
                    pass

        response_metadata = getattr(response, "response_metadata", None)
        if response_metadata is not None:
            summary["response_metadata_type"] = type(response_metadata).__name__
            summary["response_metadata_keys"] = self._safe_list_keys(response_metadata)

        usage_metadata = getattr(response, "usage_metadata", None)
        if usage_metadata is not None:
            summary["usage_metadata_type"] = type(usage_metadata).__name__
            summary["usage_metadata_keys"] = self._safe_list_keys(usage_metadata)

        choices = getattr(response, "choices", None)
        if isinstance(choices, list) and choices:
            first_choice = choices[0]
            summary["has_choices"] = True
            message = getattr(first_choice, "message", None)
            if message is not None:
                summary["choice_message_type"] = type(message).__name__
                choice_response_metadata = getattr(message, "response_metadata", None)
                if choice_response_metadata is not None:
                    summary["choice_response_metadata_keys"] = self._safe_list_keys(choice_response_metadata)
                choice_usage_metadata = getattr(message, "usage_metadata", None)
                if choice_usage_metadata is not None:
                    summary["choice_usage_metadata_keys"] = self._safe_list_keys(choice_usage_metadata)
        else:
            summary["has_choices"] = False

        return summary

    def capture_final_chunk(self, chunk: Any):
        self.final_chunk_summary = self._summarize_response(chunk)

    def _record_usage(self, response):
        usage = getattr(response, "usage", None)
        if not usage:
            if len(self.debug_samples) < 3:
                self.debug_samples.append(self._summarize_response(response))
            return

        usage_dump = None
        model_dump = getattr(usage, "model_dump", None)
        if callable(model_dump):
            try:
                usage_dump = model_dump()
            except Exception:
                usage_dump = None

        def _read_usage_value(*names: str) -> int:
            for name in names:
                value = getattr(usage, name, None)
                if value is None and isinstance(usage_dump, dict):
                    value = usage_dump.get(name)
                if value is not None:
                    try:
                        return int(value)
                    except Exception:
                        continue
            return 0

        prompt_tokens = _read_usage_value("prompt_tokens", "input_tokens")
        completion_tokens = _read_usage_value("completion_tokens", "output_tokens")
        if prompt_tokens or completion_tokens:
            self.records.append({
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
            })
        elif len(self.debug_samples) < 3:
            self.debug_samples.append(self._summarize_response(response))

    def _sanitize_chunk(self, chunk: Any) -> Any:
        self._record_usage(chunk)

        usage = getattr(chunk, "usage", None)
        usage_attrs = ("prompt_tokens", "completion_tokens", "total_tokens")
        usage_values = [getattr(usage, attr, None) for attr in usage_attrs] if usage is not None else []

        if usage is not None and all(value is None for value in usage_values):
            try:
                setattr(chunk, "usage", None)
                return chunk
            except Exception:
                pass

        if usage is not None and any(value is None for value in usage_values):
            try:
                for attr in usage_attrs:
                    if getattr(usage, attr, None) is None:
                        setattr(usage, attr, 0)
                return chunk
            except Exception:
                pass

        model_dump = getattr(chunk, "model_dump", None)
        if callable(model_dump):
            try:
                data = model_dump()
                usage_dict = data.get("usage")
                if isinstance(usage_dict, dict):
                    if all(usage_dict.get(attr) is None for attr in usage_attrs):
                        data["usage"] = None
                    else:
                        for attr in usage_attrs:
                            if usage_dict.get(attr) is None:
                                usage_dict[attr] = 0
                    model_validate = getattr(type(chunk), "model_validate", None)
                    if callable(model_validate):
                        return model_validate(data)
                    return type(chunk)(**data)
            except Exception:
                pass

        return chunk

    def patch_chat_model(self, llm, force_non_stream: bool = False):
        if self._patched:
            return

        patched_any = False

        targets = []
        for attr_name in ("client", "async_client", "root_client", "root_async_client"):
            client = getattr(llm, attr_name, None)
            if not client:
                continue

            direct_create = getattr(client, "create", None)
            if callable(direct_create):
                targets.append((client, "create", direct_create))

            chat = getattr(client, "chat", None)
            completions = getattr(chat, "completions", None) if chat else None
            chat_create = getattr(completions, "create", None) if completions else None
            if callable(chat_create):
                targets.append((completions, "create", chat_create))

        for owner, method_name, create_fn in targets:
            if getattr(create_fn, "_usage_wrapped", False):
                patched_any = True
                continue

            if asyncio.iscoroutinefunction(create_fn):
                @functools.wraps(create_fn)
                async def async_wrapper(*args, __orig=create_fn, __force_non_stream=force_non_stream, **kwargs):
                    if __force_non_stream:
                        kwargs["stream"] = False
                        kwargs.pop("stream_options", None)
                    response = await __orig(*args, **kwargs)
                    if type(response).__name__ == "AsyncStream":
                        return SanitizedAsyncStreamWrapper(response, self)
                    if type(response).__name__ == "Stream":
                        return SanitizedStreamWrapper(response, self)
                    self._record_usage(response)
                    return response

                async_wrapper._usage_wrapped = True
                setattr(owner, method_name, async_wrapper)
            else:
                @functools.wraps(create_fn)
                def sync_wrapper(*args, __orig=create_fn, __force_non_stream=force_non_stream, **kwargs):
                    if __force_non_stream:
                        kwargs["stream"] = False
                        kwargs.pop("stream_options", None)
                    response = __orig(*args, **kwargs)
                    if type(response).__name__ == "Stream":
                        return SanitizedStreamWrapper(response, self)
                    if type(response).__name__ == "AsyncStream":
                        return SanitizedAsyncStreamWrapper(response, self)
                    self._record_usage(response)
                    return response

                sync_wrapper._usage_wrapped = True
                setattr(owner, method_name, sync_wrapper)

            patched_any = True

        self._patched = patched_any


def clean_react_output(text: str) -> str:
    """
    translated ReAct Agent translated,translated
    
    Args:
        text: translated LLM translated
        
    Returns:
        translated
    """
    if not text:
        return text
    
    lines = text.split('\n')
    cleaned_lines = []
    
    for line in lines:
        if line.strip() == '**':
            continue
        
        if 'Action:' in line or 'Action Input:' in line:
            line = line.replace('**', '')
            line = re.sub(r'\s+', ' ', line).strip()
            
        cleaned_lines.append(line)
    
    return '\n'.join(cleaned_lines)


class VulnReActAgent:
    """
    translated ReAct translated
    
    translated LangChain ReAct translated,translated AI translated
    """
    
    REACT_PROMPT_TEMPLATE = """Answer the following questions as best you can. You have access to the following tools:

{tools}

Use the following format STRICTLY:

Question: the input question you must answer
Thought: you should always think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action (must be valid JSON)
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question

CRITICAL RULES: 
- Action MUST start with "Action: " followed by exactly one tool name from [{tool_names}]
- DO NOT use markdown formatting like **, *, or ``` in Action lines
- DO NOT add extra text after Action or Action Input
- Action Input MUST be valid JSON format, e.g., {{"function_name": "do_system", "version": "pre"}}
- Do not repeat the same tool call with the same parameters
- When you have enough information, use the submit_analysis tool to provide your final verdict
- After calling submit_analysis, you MUST stop and wait for Final Answer

Begin!

{system_prompt}

{few_shot_examples}

Question: {input}
Thought: {agent_scratchpad}"""

    RESULT_REPAIR_PROMPT = """You are repairing the final output of a vulnerability-analysis agent.

Convert the following raw analysis text into ONE valid JSON object that matches this schema as closely as possible:

{
  "vulnerability_found": "Yes/No/Unknown",
  "scenario_match": "Yes/No/Unknown",
  "property_match": "Yes/No/Unknown",
  "vulnerability_type": "CWE-XXX or short vulnerability type",
  "severity": "High/Medium/Low/None/Unknown",
  "vulnerable_code_location": "Description of where the vulnerability exists",
  "vulnerability_details": {
    "root_cause": "Explain the root cause",
    "attack_vector": "How it can be exploited",
    "impact": "Potential impact"
  },
  "fix_analysis": {
    "is_fixed": "Yes/No/Partial/Unknown",
    "fix_description": "How the newer version addresses the issue"
  },
  "evidence": {
    "data_flow_trace": "Concrete flow chain if available",
    "dangerous_operations": "Dangerous operations if available",
    "input_sources": "Input sources if available"
  },
  "confidence": "High/Medium/Low/Unknown",
  "reason": ["short point 1", "short point 2"]
}

Rules:
- Output ONLY valid JSON. No markdown, no explanation.
- Preserve the meaning of the raw analysis; do not invent evidence.
- If a field is missing, use "Unknown", "Not analyzed", or [] as appropriate.
- If the text clearly states a real vulnerability exists in the analyzed function, set "vulnerability_found" to "Yes".
- If the text clearly states the patched version mitigates the issue, set fix_analysis.is_fixed to "Yes" or "Partial".

Raw analysis text:
{raw_output}
"""
    
    def __init__(
        self,
        pre_pseudo_file: str,
        post_pseudo_file: str,
        pre_binary_name: str,
        post_binary_name: str,
        model_name: str = DEFAULT_LLM_CONFIG_KEY,
        temperature: float = 0,
        max_iterations: int = 20,
        ida_service_url: str = "http://10.12.189.21:5000",
        send_message: Optional[Callable] = None,
        history_dir: Optional[str] = None,
        terminal_trace_file: Optional[str] = None
    ):
        """
        translated ReAct Agent
        
        Args:
            pre_pseudo_file: translated
            post_pseudo_file: translated
            pre_binary_name: translated
            post_binary_name: translated
            model_name: LLM translated(translated config.ini translated LLM.{model_name} translated)
            temperature: translated
            max_iterations: translated
            ida_service_url: IDA translated
            send_message: translated
            history_dir: translated
        """
        self.pre_pseudo_file = pre_pseudo_file
        self.post_pseudo_file = post_pseudo_file
        self.pre_binary_name = pre_binary_name
        self.post_binary_name = post_binary_name
        self.model_config_name = model_name  # translated,translated "GPT", "DeepSeek" translated
        self.temperature = temperature
        self.max_iterations = max_iterations
        self.ida_service_url = ida_service_url
        self.send_message = send_message
        self.history_dir = history_dir
        self.terminal_trace_file = terminal_trace_file
        
        self._load_llm_config(model_name)
        
        self.tool_context = VulnToolContext(
            pre_pseudo_file=pre_pseudo_file,
            post_pseudo_file=post_pseudo_file,
            pre_binary_name=pre_binary_name,
            post_binary_name=post_binary_name,
            ida_service_url=ida_service_url,
            history_dir=history_dir,
            llm=None  # translated None,LLM translated
        )
        self.tools = create_vuln_tools(self.tool_context)
        self.usage_tracker = LLMUsageTracker()
        self.llm = self._create_llm()
        self.tool_context.llm = self.llm  # translated LLM translated
        self.raw_usage_recorder = RawUsageRecorder()
        self.raw_usage_recorder.patch_chat_model(self.llm)
        
        self.agent = self._create_agent()
        self.agent_executor = self._create_executor()
        
        logger.info(f"VulnReActAgent translated: model={self.model_name}, max_iter={max_iterations}")
    
    def _load_llm_config(self, model_config_name: str):
        """translated config.ini translated LLM translated"""
        config_section = f"LLM.{model_config_name}"
        try:
            self.api_key = config_manager.config[config_section]["api_key"]
            self.base_url = config_manager.config[config_section]["base_url"]
            self.model_name = config_manager.config[config_section]["model_name"]
            logger.info(f"translated LLM: {config_section} -> {self.model_name}")
        except KeyError as e:
            fallback_key = config_manager.resolve_llm_key(preferred=DEFAULT_LLM_CONFIG_KEY)
            logger.warning(f"Missing config section {config_section}, fallback to LLM.{fallback_key}: {e}")
            try:
                fallback_section = f"LLM.{fallback_key}"
                self.api_key = config_manager.config[fallback_section]["api_key"]
                self.base_url = config_manager.config[fallback_section]["base_url"]
                self.model_name = config_manager.config[fallback_section]["model_name"]
            except KeyError:
                logger.warning("Config-based LLM fallback failed, trying environment variables")
                self.api_key = os.environ.get("OPENAI_API_KEY", "")
                self.base_url = os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1")
                self.model_name = model_config_name

    
    def _create_llm(self) -> ChatOpenAI:
        """translated LLM translated"""
        return ChatOpenAI(
            model=self.model_name,
            temperature=self.temperature,
            api_key=self.api_key,
            base_url=self.base_url,
            max_tokens=4096,
            streaming=False
        )
    def _create_agent(self):
        """translated ReAct Agent"""
        prompt = PromptTemplate(
            template=self.REACT_PROMPT_TEMPLATE,
            input_variables=["input", "agent_scratchpad", "tools", "tool_names"],
            partial_variables={
                "system_prompt": VULN_REACT_SYSTEM_PROMPT,
                "few_shot_examples": format_few_shot_examples()
            }
        )
        
        return create_react_agent(
            llm=self.llm,
            tools=self.tools,
            prompt=prompt,
        )
    
    def _handle_parsing_error(self, error: Exception) -> str:
        """
        translated Agent translated
        
        translated LLM translated ReAct translated,translated
        """
        error_msg = str(error)
        logger.warning(f"Agent translated: {error_msg}")

        
        if "is not a valid tool" in error_msg or "Could not parse LLM output" in error_msg:
            return (
                "Invalid output format detected. Please follow the EXACT format:\n"
                "Action: <tool_name>\n"
                "Action Input: <valid_json>\n\n"
                "Do NOT use markdown formatting (**, *, ```) in Action lines.\n"
                "Available tools: get_function_body, get_callers, get_callees, get_data_flow, get_sink_slice, submit_analysis"
            )
        
        return f"Parsing error: {error_msg}. Please check your output format and try again."
    
    def _create_executor(self) -> AgentExecutor:
        """translated Agent translated"""
        callbacks = []
        if self.send_message:
            callbacks.append(ReasoningStreamHandler(self.send_message))
        callbacks.append(self.usage_tracker)
        
        return AgentExecutor(
            agent=self.agent,
            tools=self.tools,
            max_iterations=self.max_iterations,
            verbose=True,
            handle_parsing_errors=True,
            return_intermediate_steps=True,
            callbacks=callbacks
        )
    
    async def analyze(
        self,
        function_name: str,
        code_before: str,
        code_after: str,
        vulnerability_type: str,
        cve_details: str = "",
        cwe_id: str = "",
        pre_function_name: Optional[str] = None,
        post_function_name: Optional[str] = None,
        prior_analysis_result: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        translated
        
        Args:
            function_name: translated
            code_before: translated
            code_after: translated
            vulnerability_type: translated
            cve_details: CVE translated
            cwe_id: CWE ID
            
        Returns:
            translated
        """
        logger.info(f"translated ReAct translated: {function_name}, translated: {vulnerability_type}")
        
        self.tool_context.reasoning_chain = []
        self.usage_tracker.reset()
        self.raw_usage_recorder.reset()
        self.tool_context.current_function_name = function_name
        self.tool_context.current_cve_details = cve_details or ""
        self.tool_context.current_cwe_id = cwe_id or ""
        
        repair_samples_text = format_cwe_repair_samples(cwe_id)

        target_pre_function = pre_function_name or function_name
        target_post_function = post_function_name or function_name

        input_prompt = VULN_REACT_HUMAN_PROMPT.format(
            vulnerability_type=vulnerability_type,
            cwe_id=cwe_id or "Unknown",
            pre_function_name=target_pre_function,
            post_function_name=target_post_function,
            cve_details=cve_details or "No CVE details provided.",
            repair_samples=repair_samples_text,
            code_before=code_before,
            code_after=code_after
        )
        
        try:
            result = await self._run_agent(input_prompt)
            parsed_result = await self._parse_result(result, prior_analysis_result=prior_analysis_result)
            parsed_result = self._enforce_result_consistency(parsed_result)
            parsed_result["reasoning_chain"] = self.tool_context.reasoning_chain
            parsed_result["function_name"] = function_name
            # LLM CVE attribution post-processing
            if parsed_result.get("vulnerability_found", "Unknown") != "Unknown":
                cve_attribution = await self._llm_cve_attribution(
                    function_name=function_name,
                    cve_description=cve_details or "",
                    analysis_result=parsed_result,
                    reasoning_chain=self.tool_context.reasoning_chain,
                )
                parsed_result["CVE_Attribution"] = cve_attribution

            logger.info(f"ReAct translated: {function_name}")
            return parsed_result
            
        except Exception as e:
            logger.error(f"ReAct translated: {e}")
            return {
                "error": str(e),
                "vulnerability_found": "Unknown",
                "function_name": function_name,
                "reasoning_chain": self.tool_context.reasoning_chain
            }
    
    async def _run_agent(self, input_prompt: str) -> Dict[str, Any]:
        """translated Agent"""
        loop = asyncio.get_event_loop()
        start_time = time.time()
        def _invoke_with_terminal_trace() -> Dict[str, Any]:
            terminal_buffer = io.StringIO()
            with contextlib.redirect_stdout(terminal_buffer), contextlib.redirect_stderr(terminal_buffer):
                invoke_result = self.agent_executor.invoke({"input": input_prompt})
            terminal_output = terminal_buffer.getvalue()
            if self.terminal_trace_file and terminal_output.strip():
                try:
                    trace_dir = os.path.dirname(self.terminal_trace_file)
                    if trace_dir:
                        os.makedirs(trace_dir, exist_ok=True)
                    with open(self.terminal_trace_file, "a", encoding="utf-8") as trace_fp:
                        trace_fp.write(terminal_output)
                        if not terminal_output.endswith("\n"):
                            trace_fp.write("\n")
                except Exception as trace_error:
                    logger.warning(f"translated ReAct translated: {trace_error}")
            return invoke_result

        result = await loop.run_in_executor(None, _invoke_with_terminal_trace)

        cost_time = time.time() - start_time
        usage_records = self.raw_usage_recorder.records or self.usage_tracker.records
        if not usage_records:
            logger.warning("ReAct translated usage,translated token translated")
            if self.raw_usage_recorder.debug_samples:
                logger.warning(
                    "ReAct translated: %s",
                    json.dumps(self.raw_usage_recorder.debug_samples, ensure_ascii=False)
                )
            if self.raw_usage_recorder.final_chunk_summary:
                logger.warning(
                    "ReAct translated chunk translated: %s",
                    json.dumps(self.raw_usage_recorder.final_chunk_summary, ensure_ascii=False)
                )
            return result

        step_count = len(usage_records)
        per_step_time = cost_time / step_count if step_count else cost_time
        for idx, usage in enumerate(usage_records, 1):
            LLM_STATS.add_record(
                prompt_tokens=usage["prompt_tokens"],
                completion_tokens=usage["completion_tokens"],
                cost_time=per_step_time,
                tag=f"react_second_stage#{idx}",
                model_name=self.model_config_name
            )
            logger.info(
                f"[LLM] tag=react_second_stage#{idx} | "
                f"model={self.model_config_name} | "
                f"prompt_tokens={usage['prompt_tokens']}, "
                f"completion_tokens={usage['completion_tokens']}, "
                f"time={per_step_time:.2f}s"
            )

        return result
    
    @staticmethod
    def _extract_json_object(text: str) -> Optional[Dict[str, Any]]:
        if not isinstance(text, str) or not text.strip():
            return None

        decoder = json.JSONDecoder()
        for match in re.finditer(r"\{", text):
            try:
                parsed, _ = decoder.raw_decode(text[match.start():])
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                continue
        return None

    async def _repair_result_to_json(self, raw_output: str) -> Optional[Dict[str, Any]]:
        raw_output = str(raw_output or "").strip()
        if not raw_output:
            return None

        prompt = self.RESULT_REPAIR_PROMPT.replace("{raw_output}", raw_output[:12000])
        try:
            loop = asyncio.get_event_loop()
            from langchain.schema import HumanMessage

            response = await loop.run_in_executor(
                None,
                lambda: self.llm.invoke([HumanMessage(content=prompt)])
            )
            content = response.content if hasattr(response, "content") else str(response)
            return self._extract_json_object(content)
        except Exception as e:
            logger.warning(f"ReAct result JSON repair failed: {e}")
            return None

    @staticmethod
    def _detect_vulnerability_type(raw_output: str) -> str:
        text = str(raw_output or "")
        cwe_match = re.search(r"\bCWE-\d+\b", text, re.IGNORECASE)
        if cwe_match:
            return cwe_match.group(0).upper()

        lowered = text.lower()
        keyword_map = [
            ("command injection", "Command Injection"),
            ("sql injection", "SQL Injection"),
            ("path traversal", "Path Traversal"),
            ("directory traversal", "Path Traversal"),
            ("stack-based buffer overflow", "Stack-based Buffer Overflow"),
            ("buffer overflow", "Buffer Overflow"),
            ("stack overflow", "Stack Overflow"),
            ("heap overflow", "Heap Overflow"),
            ("out-of-bounds write", "Out-of-Bounds Write"),
            ("out-of-bounds read", "Out-of-Bounds Read"),
            ("use-after-free", "Use-After-Free"),
            ("double free", "Double Free"),
            ("format string", "Format String"),
            ("integer overflow", "Integer Overflow"),
            ("null pointer dereference", "Null Pointer Dereference"),
            ("cross-site scripting", "Cross-Site Scripting"),
            ("xss", "Cross-Site Scripting"),
            ("deserialization", "Insecure Deserialization"),
        ]
        for needle, label in keyword_map:
            if needle in lowered:
                return label
        return "Unknown"

    @staticmethod
    def _infer_fix_status(raw_output: str) -> str:
        lowered = str(raw_output or "").lower()
        positive_fix_signals = [
            "patch replaces",
            "patched version",
            "the patch",
            "prevents the overflow",
            "preventing the overflow",
            "adds validation",
            "adds bounds checking",
            "limits the copy",
            "eliminating the risk",
            "fixed by",
            "mitigates",
        ]
        partial_fix_signals = ["partial", "partially", "reduces the risk"]
        if any(signal in lowered for signal in partial_fix_signals):
            return "Partial"
        if any(signal in lowered for signal in positive_fix_signals):
            return "Yes"
        return "Unknown"

    @staticmethod
    def _infer_severity_from_text(raw_output: str, vulnerability_found: str) -> str:
        lowered = str(raw_output or "").lower()
        if vulnerability_found == "No":
            return "None"
        if vulnerability_found != "Yes":
            return "Unknown"
        if any(word in lowered for word in ["critical", "arbitrary code execution", "execute arbitrary", "remote code execution", "command injection"]):
            return "High"
        if any(word in lowered for word in ["high", "buffer overflow", "stack overflow", "heap overflow", "out-of-bounds", "use-after-free", "double free"]):
            return "High"
        if any(word in lowered for word in ["medium", "sql injection", "path traversal", "format string", "cross-site scripting", "xss"]):
            return "Medium"
        return "Medium"

    @staticmethod
    def _infer_location_from_text(raw_output: str) -> str:
        text = str(raw_output or "").strip()
        location_match = re.search(
            r"(?:in|via|at)\s+(`[^`]+`|\"[^\"]+\"|[A-Za-z_][A-Za-z0-9_]*)",
            text,
            re.IGNORECASE,
        )
        if location_match:
            return location_match.group(0)
        return "Not analyzed"

    @staticmethod
    def _infer_dangerous_operations(raw_output: str) -> str:
        lowered = str(raw_output or "").lower()
        operations = []
        for op in ["system", "strcpy", "strncpy", "sprintf", "snprintf", "memcpy", "strcat", "gets", "scanf", "sscanf", "exec", "popen"]:
            if op in lowered:
                operations.append(op)
        return ", ".join(dict.fromkeys(operations)) if operations else "Not analyzed"

    @staticmethod
    def _split_reasons(raw_output: str) -> List[str]:
        text = " ".join(str(raw_output or "").strip().split())
        if not text:
            return []
        parts = re.split(r"(?<=[.!?])\s+", text)
        return [part.strip() for part in parts if part.strip()][:4]

    def _infer_parse_fallback(self, raw_output: str) -> Optional[Dict[str, Any]]:
        text = str(raw_output or "").strip()
        if not text:
            return None

        lowered = text.lower()
        negative_signals = [
            "no vulnerability",
            "not vulnerable",
            "does not contain a vulnerability",
            "no security issue",
            "insufficient evidence",
            "cannot confirm",
            "unable to confirm",
            "no attacker-controlled input",
            "safe implementation",
        ]
        positive_signals = [
            "contains a",
            "contains an",
            "is vulnerable to",
            "vulnerability in",
            "allows an attacker",
            "allows remote attackers",
            "command injection",
            "stack overflow",
            "buffer overflow",
            "stack-based buffer overflow",
            "heap overflow",
            "out-of-bounds write",
            "out-of-bounds read",
            "use-after-free",
            "double free",
            "format string",
            "sql injection",
            "path traversal",
            "cross-site scripting",
            "xss",
            "without any bounds checking",
            "without validation",
            "without sanitization",
            "attacker-controlled input",
            "executed via `system",
            "executed via system",
            "directly embedded into a shell command",
            "copied into",
        ]

        has_negative = any(signal in lowered for signal in negative_signals)
        has_positive = any(signal in lowered for signal in positive_signals)
        if not has_positive and not has_negative:
            return None

        vulnerability_found = "Unknown"
        scenario_match = "Unknown"
        if has_positive and not has_negative:
            vulnerability_found = "Yes"
            scenario_match = "Yes"
        elif has_negative and not has_positive:
            vulnerability_found = "No"
            scenario_match = "No"

        fix_status = self._infer_fix_status(text)
        reasons = self._split_reasons(text) or [
            "Fallback parser inferred a weak structured result from non-JSON raw output."
        ]

        return {
            "raw_output": text,
            "parse_error": True,
            "fallback_inferred": True,
            "fallback_source": "heuristic_raw_output",
            "vulnerability_found": vulnerability_found,
            "scenario_match": scenario_match,
            "property_match": "Yes" if fix_status == "Yes" and vulnerability_found == "Yes" else "Unknown",
            "vulnerability_type": self._detect_vulnerability_type(text),
            "severity": self._infer_severity_from_text(text, vulnerability_found),
            "vulnerable_code_location": self._infer_location_from_text(text),
            "vulnerability_details": {
                "root_cause": reasons[0],
                "attack_vector": "Not analyzed",
                "impact": "Not analyzed"
            },
            "fix_analysis": {
                "is_fixed": fix_status,
                "fix_description": reasons[-1] if fix_status in {"Yes", "Partial"} else "Not analyzed"
            },
            "evidence": {
                "data_flow_trace": "Not analyzed",
                "dangerous_operations": self._infer_dangerous_operations(text),
                "input_sources": "Not analyzed"
            },
            "confidence": "Low",
            "reason": reasons
        }

    def _backfill_prior_stage_labels(
        self,
        parsed_result: Dict[str, Any],
        prior_analysis_result: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        if not isinstance(parsed_result, dict) or not isinstance(prior_analysis_result, dict):
            return parsed_result

        current = self._normalize_yes_no(parsed_result.get("scenario_match"))
        prior = prior_analysis_result.get("scenario_match")
        if current in {"", "unknown"} and self._normalize_yes_no(prior) in {"yes", "no"}:
            parsed_result["scenario_match"] = prior

        return parsed_result

    async def _parse_result(
        self,
        result: Dict[str, Any],
        prior_analysis_result: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """?? Agent ????"""
        output = result.get("output", "")
        intermediate_steps = result.get("intermediate_steps", [])

        parsed = self._extract_json_object(output)
        if parsed is not None:
            parsed = self._backfill_prior_stage_labels(parsed, prior_analysis_result)
            parsed["intermediate_steps_count"] = len(intermediate_steps)
            return parsed

        repaired = await self._repair_result_to_json(output)
        if repaired is not None:
            repaired = self._backfill_prior_stage_labels(repaired, prior_analysis_result)
            repaired["raw_output"] = output
            repaired["parse_error"] = True
            repaired["repair_applied"] = True
            repaired["intermediate_steps_count"] = len(intermediate_steps)
            return repaired

        fallback = self._infer_parse_fallback(output)
        if fallback is not None:
            fallback = self._backfill_prior_stage_labels(fallback, prior_analysis_result)
            fallback["intermediate_steps_count"] = len(intermediate_steps)
            return fallback

        return {
            "raw_output": output,
            "vulnerability_found": "Unknown",
            "parse_error": True,
            "intermediate_steps_count": len(intermediate_steps)
        }

    @staticmethod
    def _normalize_yes_no(value: Any) -> str:
        return str(value or "").strip().lower()

    @staticmethod
    def _is_meaningful_evidence_text(value: Any) -> bool:
        text = str(value or "").strip().lower()
        if not text:
            return False
        if text.startswith("unknown") or text.startswith("not analyzed") or text == "n/a":
            return False
        return True

    def _enforce_result_consistency(self, parsed_result: Dict[str, Any]) -> Dict[str, Any]:
        parsed_result = self._normalize_result_structure(parsed_result)
        scenario_match = self._normalize_yes_no(parsed_result.get("scenario_match"))
        property_match = self._normalize_yes_no(parsed_result.get("property_match"))

        parsed_result["Scenario_match & Property_match"] = (
            "Yes" if scenario_match == "yes" and property_match == "yes" else "No"
        )

        if scenario_match == "no":
            parsed_result["vulnerability_found"] = "No"
            parsed_result["severity"] = "None"
            reason = parsed_result.get("reason")
            if isinstance(reason, list):
                consistency_note = (
                    "Consistency rule applied: scenario_match is No, so this function "
                    "cannot keep vulnerability_found = Yes."
                )
                if consistency_note not in reason:
                    reason.append(consistency_note)

        return parsed_result

    def _normalize_result_structure(self, parsed_result: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(parsed_result, dict):
            return parsed_result

        vulnerability_details = parsed_result.get("vulnerability_details")
        if not isinstance(vulnerability_details, dict):
            vulnerability_details = {}
            parsed_result["vulnerability_details"] = vulnerability_details

        for nested_key, flat_key in (
            ("root_cause", "root_cause"),
            ("attack_vector", "attack_vector"),
            ("impact", "impact"),
        ):
            nested_value = vulnerability_details.get(nested_key)
            if not self._is_meaningful_evidence_text(nested_value):
                flat_value = parsed_result.get(flat_key)
                if self._is_meaningful_evidence_text(flat_value):
                    vulnerability_details[nested_key] = flat_value

        fix_analysis = parsed_result.get("fix_analysis")
        if not isinstance(fix_analysis, dict):
            fix_analysis = {}
            parsed_result["fix_analysis"] = fix_analysis

        for nested_key, flat_key in (
            ("is_fixed", "is_fixed"),
            ("fix_description", "fix_description"),
        ):
            nested_value = fix_analysis.get(nested_key)
            if not self._is_meaningful_evidence_text(nested_value):
                flat_value = parsed_result.get(flat_key)
                if self._is_meaningful_evidence_text(flat_value):
                    fix_analysis[nested_key] = flat_value

        evidence = parsed_result.get("evidence")
        if not isinstance(evidence, dict):
            evidence = {}
            parsed_result["evidence"] = evidence

        for nested_key, flat_key in (
            ("data_flow_trace", "data_flow_trace"),
            ("dangerous_operations", "dangerous_operations"),
            ("input_sources", "input_sources"),
        ):
            nested_value = evidence.get(nested_key)
            if not self._is_meaningful_evidence_text(nested_value):
                flat_value = parsed_result.get(flat_key)
                if self._is_meaningful_evidence_text(flat_value):
                    evidence[nested_key] = flat_value

        return parsed_result

    def _has_sufficient_attribution_evidence(self, analysis_result: Dict[str, Any]) -> bool:
        evidence = analysis_result.get("evidence", {}) or {}
        return (
            self._is_meaningful_evidence_text(evidence.get("data_flow_trace"))
            and self._is_meaningful_evidence_text(evidence.get("dangerous_operations"))
            and self._is_meaningful_evidence_text(evidence.get("input_sources"))
        )

    _CVE_ATTRIBUTION_PROMPT = """You are a binary vulnerability analyst performing CVE attribution.

## CVE Description
{cve_description}

## Function Under Analysis
Name: {function_name}

Pre-patch code:
```c
{function_code}
```

## Vulnerability Analysis Result (from ReAct agent)
- vulnerability_found: {vulnerability_found}
- scenario_match: {scenario_match}
- property_match: {property_match}
- root_cause: {root_cause}
- data_flow_trace: {data_flow_trace}
- input_sources: {input_sources}
- dangerous_operations: {dangerous_operations}
- attack_vector: {attack_vector}

## Evidence Collected During Analysis (tool observations)
{evidence_summary}

## Your Task
Based on ALL the evidence above, determine whether this function is the root cause function of the CVE.

Priority rules:
1. Prefer the actual vulnerable sink / bug carrier over the HTTP entry point, request parser, dispatcher, wrapper, or caller.
2. If attacker-controlled data reaches a dangerous write, overflow-triggering operation, or other decisive vulnerable sink inside THIS function, then THIS function should usually be marked as `is_cve_root_function = Yes`.
3. Prefer the function where the out-of-bounds write, dangerous copy, or bounds-check failure actually occurs over upstream functions that merely receive, parse, or forward the data.
4. Only mark this function as `intermediate` or `helper` when the decisive vulnerable operation clearly happens in a different function.
5. If `scenario_match` is not `Yes`, then `is_cve_root_function` MUST be `No`.
6. Missing visibility into a helper body, source origin, caller chain, or validation helper is NOT positive evidence.
7. `Unknown`, `Not analyzed`, or evidence gaps are NOT sufficient to mark `is_cve_root_function = Yes`.
8. Ordinary data carrying, JSON construction, configuration reads/writes, logging, serialization, or display logic do NOT constitute a CWE-77 root cause by themselves, even if the data may be attacker-controlled.
9. If the observed evidence more strongly suggests a different bug class than the target CWE/CVE scenario, do NOT force this function to be the CVE root function.

To answer this, reason through:
1. Does this function contain the specific bug described by the CVE?
2. Is there a plausible call chain from the CVE's attack entry point to this function?
3. Through that call chain, does attacker-controlled data (as described in the CVE) flow into this function's vulnerable parameter?
4. Or can the CVE's impact be fully explained by a different function in the call chain?

Continue reasoning until you can determine whether the data origin is:
- External input controllable by the attacker described in the CVE → is_cve_root_function = Yes
- Constant/hardcoded value not reachable by attacker → is_cve_root_function = No
- Unclear from available evidence → state your best judgment with low confidence

Output ONLY valid JSON in this exact format:
{{
  "is_cve_root_function": "Yes" or "No",
  "attack_chain_role": "entry point" or "intermediate" or "helper" or "unrelated",
  "can_other_functions_explain_cve": "Yes" or "No",
  "reasoning": "Detailed explanation of your attribution decision",
  "confidence": <integer 0-100>
}}"""

    async def _llm_cve_attribution(
        self,
        function_name: str,
        cve_description: str,
        analysis_result: Dict[str, Any],
        reasoning_chain: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """translated LLM translated CVE translated"""
        if not cve_description:
            return {"is_cve_root_function": "Unknown", "confidence": 0, "reasoning": "No CVE description provided"}

        if self._normalize_yes_no(analysis_result.get("scenario_match")) != "yes":
            return {
                "is_cve_root_function": "No",
                "attack_chain_role": "unrelated",
                "can_other_functions_explain_cve": "Yes",
                "reasoning": "scenario_match is not Yes, so this function cannot be the CVE root function.",
                "confidence": 95,
            }

        if self._normalize_yes_no(analysis_result.get("vulnerability_found")) != "yes":
            return {
                "is_cve_root_function": "No",
                "attack_chain_role": "unrelated",
                "can_other_functions_explain_cve": "Yes",
                "reasoning": "vulnerability_found is not Yes after consistency checks, so root attribution is rejected.",
                "confidence": 95,
            }

        if not self._has_sufficient_attribution_evidence(analysis_result):
            return {
                "is_cve_root_function": "No",
                "attack_chain_role": "helper",
                "can_other_functions_explain_cve": "Yes",
                "reasoning": "Evidence is insufficient for CVE root attribution because data_flow_trace, dangerous_operations, or input_sources remain unknown or not analyzed.",
                "confidence": 90,
            }

        function_code = ""
        for version in ("pre", "post"):
            idx = self.tool_context.get_index(version)
            if idx:
                code = idx.get_function(function_name)
                if code:
                    function_code = code[:3000]
                    break

        evidence_parts = []
        for step in reasoning_chain:
            tool = step.get("tool", "")
            inp = step.get("input", {})
            out = step.get("output", "")
            evidence_parts.append(f"[{tool}] input={inp}\n{out[:600]}")
        evidence_summary = "\n\n---\n".join(evidence_parts) if evidence_parts else "No tool observations recorded."

        evidence = analysis_result.get("evidence", {})
        prompt = self._CVE_ATTRIBUTION_PROMPT.format(
            cve_description=cve_description,
            function_name=function_name,
            function_code=function_code or "Not available",
            vulnerability_found=analysis_result.get("vulnerability_found", "Unknown"),
            scenario_match=analysis_result.get("scenario_match", "Unknown"),
            property_match=analysis_result.get("property_match", "Unknown"),
            root_cause=analysis_result.get("vulnerability_details", {}).get("root_cause", "Not analyzed"),
            data_flow_trace=evidence.get("data_flow_trace", "Not analyzed"),
            input_sources=evidence.get("input_sources", "Not analyzed"),
            dangerous_operations=evidence.get("dangerous_operations", "Not analyzed"),
            attack_vector=analysis_result.get("vulnerability_details", {}).get("attack_vector", "Not analyzed"),
            evidence_summary=evidence_summary,
        )

        try:
            loop = asyncio.get_event_loop()
            from langchain.schema import HumanMessage
            response = await loop.run_in_executor(
                None,
                lambda: self.llm.invoke([HumanMessage(content=prompt)])
            )
            content = response.content if hasattr(response, "content") else str(response)
            json_match = re.search(r'\{[\s\S]*\}', content)
            if json_match:
                return json.loads(json_match.group())
            return {"is_cve_root_function": "Unknown", "confidence": 0, "reasoning": content}
        except Exception as e:
            logger.error(f"LLM CVE attribution failed for {function_name}: {e}")
            return {"is_cve_root_function": "Unknown", "confidence": 0, "reasoning": str(e)}
    
    def analyze_sync(
        self,
        function_name: str,
        code_before: str,
        code_after: str,
        vulnerability_type: str,
        cve_details: str = "",
        cwe_id: str = ""
    ) -> Dict[str, Any]:
        """
        translated
        
        translated
        """
        return asyncio.run(self.analyze(
            function_name=function_name,
            code_before=code_before,
            code_after=code_after,
            vulnerability_type=vulnerability_type,
            cve_details=cve_details,
            cwe_id=cwe_id
        ))


class VulnReActRefiner:
    """
    translated ReAct Agent translated
    
    translated RAG translated
    """
    
    def __init__(
        self,
        log_file: str,
        pre_binary_name: str,
        post_binary_name: str,
        pre_pseudo_file: str,
        post_pseudo_file: str,
        model_name: str = DEFAULT_LLM_CONFIG_KEY,
        max_iterations: int = 20,
        send_message: Optional[Callable] = None,
        history_dir: Optional[str] = None
    ):
        """
        translated
        
        Args:
            log_file: translated
            pre_binary_name: translated
            post_binary_name: translated
            pre_pseudo_file: translated
            post_pseudo_file: translated
            model_name: translated
            max_iterations: translated
            send_message: translated
            history_dir: translated
        """
        self.log_file = log_file
        self.context_log = f"{log_file}.react_ctx"
        self.terminal_trace_log = f"{log_file}.react_terminal"
        self.pre_binary_name = pre_binary_name
        self.post_binary_name = post_binary_name
        self.pre_pseudo_file = pre_pseudo_file
        self.post_pseudo_file = post_pseudo_file
        self.model_name = model_name
        self.max_iterations = max_iterations
        self.send_message = send_message
        self.history_dir = history_dir
        
        self.agent = VulnReActAgent(
            pre_pseudo_file=pre_pseudo_file,
            post_pseudo_file=post_pseudo_file,
            pre_binary_name=pre_binary_name,
            post_binary_name=post_binary_name,
            model_name=model_name,
            max_iterations=max_iterations,
            send_message=send_message,
            history_dir=history_dir,
            terminal_trace_file=self.terminal_trace_log
        )
        
        self._task_cache: Dict[str, Any] = {}
        
        logger.info("VulnReActRefiner translated")
    
    async def refine(
        self,
        fa: str,
        fb: str,
        cve_details: str = "",
        cwe: str = "",
        work_mode: str = "reproduction",
        prior_analysis_result: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        translated
        
        Args:
            fa: translated
            fb: translated
            cve_details: CVE translated
            cwe: CWE translated
            work_mode: translated
            
        Returns:
            translated
        """
        cache_key = f"{os.path.basename(fa)}_{os.path.basename(fb)}"
        if cache_key in self._task_cache:
            logger.info(f"translated {cache_key} translated")
            return self._task_cache[cache_key]
        
        try:
            with open(fa, 'r', encoding='utf-8') as f:
                code_before = f.read()
            with open(fb, 'r', encoding='utf-8') as f:
                code_after = f.read()
        except Exception as e:
            logger.error(f"translated: {e}")
            return f"translated: {str(e)}"
        
        pre_function_name = os.path.basename(fa).split('.')[0]
        post_function_name = os.path.basename(fb).split('.')[0]
        function_name = pre_function_name
        
        if self.send_message:
            await self.send_message(
                f"🔍 translated ReAct translated: {function_name}",
                message_type="message",
                agent="Detection Agent"
            )
        
        result = await self.agent.analyze(
            function_name=function_name,
            code_before=code_before,
            code_after=code_after,
            vulnerability_type=cwe or "Unknown",
            cve_details=cve_details,
            cwe_id=cwe,
            pre_function_name=pre_function_name,
            post_function_name=post_function_name,
            prior_analysis_result=prior_analysis_result
        )
        
        result_str = json.dumps(result, indent=2, ensure_ascii=False)
        
        try:
            with open(self.log_file, 'a', encoding='utf-8') as w:
                w.write(f"=== {os.path.basename(fa)} vs {os.path.basename(fb)} (ReActtranslated) ===\n")
                w.write(result_str + "\n\n")
            
            with open(self.context_log, 'a', encoding='utf-8') as w:
                w.write(f"=== {os.path.basename(fa)} vs {os.path.basename(fb)} ===\n")
                w.write("Reasoning Chain:\n")
                for step in result.get("reasoning_chain", []):
                    w.write(f"  Tool: {step.get('tool')}\n")
                    w.write(f"  Input: {step.get('input')}\n")
                    w.write(f"  Output: {step.get('output')}\n\n")
                w.write("\n")
                
        except Exception as e:
            logger.error(f"translated: {e}")
        
        self._task_cache[cache_key] = result_str
        
        if self.send_message:
            vuln_found = result.get("vulnerability_found", "Unknown")
            severity = result.get("severity", "Unknown")
            await self.send_message(
                f"✅ ReAct translated: {function_name}\n"
                f"   translated: {vuln_found}, translated: {severity}",
                message_type="message",
                agent="Detection Agent"
            )
        
        return result_str


async def react_analyze_function_pair(
    fa: str,
    fb: str,
    pre_pseudo_file: str,
    post_pseudo_file: str,
    pre_binary_name: str,
    post_binary_name: str,
    cve_details: str = "",
    cwe: str = "",
    send_message: Optional[Callable] = None,
    model_name: str = DEFAULT_LLM_CONFIG_KEY
) -> str:
    """
    translated ReAct Agent translated
    
    translated,translated
    
    Args:
        fa: translated
        fb: translated
        pre_pseudo_file: translated
        post_pseudo_file: translated
        pre_binary_name: translated
        post_binary_name: translated
        cve_details: CVE translated
        cwe: CWE translated
        send_message: translated
        model_name: translated(translated config.ini translated LLM.{model_name} translated)
        
    Returns:
        translated JSON translated
    """
    agent = VulnReActAgent(
        pre_pseudo_file=pre_pseudo_file,
        post_pseudo_file=post_pseudo_file,
        pre_binary_name=pre_binary_name,
        post_binary_name=post_binary_name,
        model_name=model_name,
        send_message=send_message
    )
    
    with open(fa, 'r', encoding='utf-8') as f:
        code_before = f.read()
    with open(fb, 'r', encoding='utf-8') as f:
        code_after = f.read()
    
    function_name = os.path.basename(fa).split('.')[0]
    
    result = await agent.analyze(
        function_name=function_name,
        code_before=code_before,
        code_after=code_after,
        vulnerability_type=cwe or "Unknown",
        cve_details=cve_details,
        cwe_id=cwe
    )
    
    return json.dumps(result, indent=2, ensure_ascii=False)


__all__ = [
    'VulnReActAgent',
    'VulnReActRefiner',
    'ReasoningStreamHandler',
    'react_analyze_function_pair'
]
