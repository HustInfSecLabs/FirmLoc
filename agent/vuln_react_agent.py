# -*- coding: utf-8 -*-
"""
Vulnerability Analysis ReAct Agent

基于 LangChain ReAct 模式的漏洞分析智能体
"""
import os
import re
import json
import asyncio
from typing import Optional, Dict, Any, List, Callable
from pathlib import Path

from langchain.agents import AgentExecutor, create_react_agent
from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate
from langchain.memory import ConversationBufferWindowMemory
from langchain.callbacks.base import BaseCallbackHandler

from log import logger
from config import config_manager
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


class ReasoningStreamHandler(BaseCallbackHandler):
    """
    推理过程流式输出处理器
    
    用于可视化 Agent 的思考过程
    """
    
    def __init__(self, send_message: Optional[Callable] = None):
        """
        初始化处理器
        
        Args:
            send_message: 消息发送函数，用于实时推送到前端
        """
        self.send_message = send_message
        self.current_thought = ""
        self.step_count = 0
    
    def on_agent_action(self, action, **kwargs):
        """Agent 执行动作时的回调"""
        self.step_count += 1
        message = f"🔧 Step {self.step_count}: Using tool `{action.tool}`\n"
        message += f"   Input: {action.tool_input}"
        
        logger.info(message)
        self._dispatch_message(message, "reasoning")
    
    def on_tool_end(self, output, **kwargs):
        """工具执行完成时的回调"""
        # 截断过长的输出
        display_output = output[:300] + "..." if len(output) > 300 else output
        message = f"📋 Tool Output: {display_output}"
        
        logger.debug(message)
        self._dispatch_message(message, "tool_output")
    
    def on_agent_finish(self, finish, **kwargs):
        """Agent 完成时的回调"""
        message = f"✅ Analysis Complete (Total steps: {self.step_count})"
        
        logger.info(message)
        self._dispatch_message(message, "complete")
    
    def on_llm_start(self, serialized, prompts, **kwargs):
        """LLM 开始推理时的回调"""
        message = "🤔 Thinking..."
        self._dispatch_message(message, "thinking")

    def _dispatch_message(self, message: str, msg_type: str) -> None:
        """在同步/异步环境中安全发送消息"""
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
                logger.error(f"发送推理消息失败: {e}")
    
    async def _async_send(self, message: str, msg_type: str):
        """异步发送消息"""
        try:
            if asyncio.iscoroutinefunction(self.send_message):
                await self.send_message(message, message_type=msg_type)
            else:
                self.send_message(message, message_type=msg_type)
        except Exception as e:
            logger.error(f"发送推理消息失败: {e}")


def clean_react_output(text: str) -> str:
    """
    清理 ReAct Agent 的输出,移除可能干扰解析的格式符号
    
    Args:
        text: 原始 LLM 输出文本
        
    Returns:
        清理后的文本
    """
    if not text:
        return text
    
    lines = text.split('\n')
    cleaned_lines = []
    
    for line in lines:
        # 移除独立的 ** 行（可能是格式错误）
        if line.strip() == '**':
            continue
        
        # 处理包含 Action: 或 Action Input: 的行
        if 'Action:' in line or 'Action Input:' in line:
            # 移除所有 ** 符号（开头、中间、结尾）
            line = line.replace('**', '')
            # 清理可能的多余空格
            line = re.sub(r'\s+', ' ', line).strip()
            
        cleaned_lines.append(line)
    
    return '\n'.join(cleaned_lines)


class VulnReActAgent:
    """
    漏洞分析 ReAct 智能体
    
    使用 LangChain ReAct 模式，让 AI 自主决定需要哪些上下文信息
    """
    
    # ReAct Agent 的提示词模板
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
- When you have enough information, use the submit_analysis tool to provide your final verdict
- Do not repeat the same tool call with the same parameters
- After calling submit_analysis, you MUST stop and wait for Final Answer

Begin!

{system_prompt}

{few_shot_examples}

Question: {input}
Thought: {agent_scratchpad}"""
    
    def __init__(
        self,
        pre_pseudo_file: str,
        post_pseudo_file: str,
        pre_binary_name: str,
        post_binary_name: str,
        model_name: str = "GPT",
        temperature: float = 0,
        max_iterations: int = 50,
        ida_service_url: str = "http://10.12.189.21:5000",
        send_message: Optional[Callable] = None,
        history_dir: Optional[str] = None
    ):
        """
        初始化 ReAct Agent
        
        Args:
            pre_pseudo_file: 补丁前的伪代码文件路径
            post_pseudo_file: 补丁后的伪代码文件路径
            pre_binary_name: 补丁前二进制名称
            post_binary_name: 补丁后二进制名称
            model_name: LLM 模型配置名称（对应 config.ini 中的 LLM.{model_name} 节）
            temperature: 温度参数
            max_iterations: 最大迭代次数
            ida_service_url: IDA 服务地址
            send_message: 消息发送回调函数
            history_dir: 历史记录目录
        """
        self.pre_pseudo_file = pre_pseudo_file
        self.post_pseudo_file = post_pseudo_file
        self.pre_binary_name = pre_binary_name
        self.post_binary_name = post_binary_name
        self.model_config_name = model_name  # 配置名称，如 "GPT", "DeepSeek" 等
        self.temperature = temperature
        self.max_iterations = max_iterations
        self.ida_service_url = ida_service_url
        self.send_message = send_message
        self.history_dir = history_dir
        
        # 从 config.ini 读取 LLM 配置
        self._load_llm_config(model_name)
        
        # 初始化工具上下文
        self.tool_context = VulnToolContext(
            pre_pseudo_file=pre_pseudo_file,
            post_pseudo_file=post_pseudo_file,
            pre_binary_name=pre_binary_name,
            post_binary_name=post_binary_name,
            ida_service_url=ida_service_url,
            history_dir=history_dir
        )
        
        # 创建工具
        self.tools = create_vuln_tools(self.tool_context)
        
        # 初始化 LLM
        self.llm = self._create_llm()
        
        # 初始化 Agent
        self.agent = self._create_agent()
        self.agent_executor = self._create_executor()
        
        logger.info(f"VulnReActAgent 初始化完成: model={self.model_name}, max_iter={max_iterations}")
    
    def _load_llm_config(self, model_config_name: str):
        """从 config.ini 加载 LLM 配置"""
        config_section = f"LLM.{model_config_name}"
        try:
            self.api_key = config_manager.config[config_section]["api_key"]
            self.base_url = config_manager.config[config_section]["base_url"]
            self.model_name = config_manager.config[config_section]["model_name"]
            logger.info(f"从配置加载 LLM: {config_section} -> {self.model_name}")
        except KeyError as e:
            logger.warning(f"配置 {config_section} 不存在，尝试使用默认 GPT 配置: {e}")
            try:
                self.api_key = config_manager.config["LLM.GPT"]["api_key"]
                self.base_url = config_manager.config["LLM.GPT"]["base_url"]
                self.model_name = config_manager.config["LLM.GPT"]["model_name"]
            except KeyError:
                # 最后尝试从环境变量获取
                logger.warning("从配置文件获取失败，尝试使用环境变量")
                self.api_key = os.environ.get("OPENAI_API_KEY", "")
                self.base_url = os.environ.get("OPENAI_API_BASE", "https://api.openai.com/v1")
                self.model_name = model_config_name if model_config_name != "GPT" else "gpt-4o"
    
    def _create_llm(self) -> ChatOpenAI:
        """创建 LLM 实例"""
        return ChatOpenAI(
            model=self.model_name,
            temperature=self.temperature,
            api_key=self.api_key,
            base_url=self.base_url,
            max_tokens=4096
        )
    
    def _create_agent(self):
        """创建 ReAct Agent"""
        # 构建提示词模板
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
            prompt=prompt
        )
    
    def _handle_parsing_error(self, error: Exception) -> str:
        """
        处理 Agent 输出解析错误
        
        当 LLM 输出格式不符合 ReAct 规范时，尝试修复或给出友好提示
        """
        error_msg = str(error)
        logger.warning(f"Agent 输出解析错误: {error_msg}")
        
        # 检查是否是 Action 格式错误
        if "is not a valid tool" in error_msg or "Could not parse LLM output" in error_msg:
            return (
                "Invalid output format detected. Please follow the EXACT format:\n"
                "Action: <tool_name>\n"
                "Action Input: <valid_json>\n\n"
                "Do NOT use markdown formatting (**, *, ```) in Action lines.\n"
                "Available tools: get_function_body, get_callers, get_callees, get_data_flow, submit_analysis"
            )
        
        return f"Parsing error: {error_msg}. Please check your output format and try again."
    
    def _create_executor(self) -> AgentExecutor:
        """创建 Agent 执行器"""
        # 创建回调处理器
        callbacks = []
        if self.send_message:
            callbacks.append(ReasoningStreamHandler(self.send_message))
        
        return AgentExecutor(
            agent=self.agent,
            tools=self.tools,
            max_iterations=self.max_iterations,
            verbose=True,
            handle_parsing_errors=self._handle_parsing_error,
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
        post_function_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        执行漏洞分析
        
        Args:
            function_name: 目标函数名
            code_before: 补丁前代码
            code_after: 补丁后代码
            vulnerability_type: 漏洞类型描述
            cve_details: CVE 详情
            cwe_id: CWE ID
            
        Returns:
            分析结果字典
        """
        logger.info(f"开始 ReAct 分析: {function_name}, 漏洞类型: {vulnerability_type}")
        
        # 重置工具上下文的推理链
        self.tool_context.reasoning_chain = []
        
        # 加载并格式化 CWE 正反修复样例
        repair_samples_text = format_cwe_repair_samples(cwe_id)

        target_pre_function = pre_function_name or function_name
        target_post_function = post_function_name or function_name

        # 构建输入提示词，使用正反修复样例而不是 scenario/property
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
            # 执行 Agent
            result = await self._run_agent(input_prompt)
            
            # 解析结果
            parsed_result = self._parse_result(result)
            
            # 添加推理链到结果
            parsed_result["reasoning_chain"] = self.tool_context.reasoning_chain
            parsed_result["function_name"] = function_name
            
            logger.info(f"ReAct 分析完成: {function_name}")
            return parsed_result
            
        except Exception as e:
            logger.error(f"ReAct 分析失败: {e}")
            return {
                "error": str(e),
                "vulnerability_found": "Unknown",
                "function_name": function_name,
                "reasoning_chain": self.tool_context.reasoning_chain
            }
    
    async def _run_agent(self, input_prompt: str) -> Dict[str, Any]:
        """运行 Agent"""
        loop = asyncio.get_event_loop()
        
        # 在线程池中运行同步的 Agent
        result = await loop.run_in_executor(
            None,
            lambda: self.agent_executor.invoke({"input": input_prompt})
        )
        
        return result
    
    def _parse_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """解析 Agent 输出结果"""
        output = result.get("output", "")
        intermediate_steps = result.get("intermediate_steps", [])
        
        # 尝试解析 JSON 结果
        try:
            # 查找 JSON 块
            json_match = re.search(r'\{[\s\S]*\}', output)
            if json_match:
                parsed = json.loads(json_match.group())
                parsed["intermediate_steps_count"] = len(intermediate_steps)
                return parsed
        except json.JSONDecodeError:
            pass
        
        # 如果无法解析 JSON，返回原始输出
        return {
            "raw_output": output,
            "vulnerability_found": "Unknown",
            "parse_error": True,
            "intermediate_steps_count": len(intermediate_steps)
        }
    
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
        同步版本的分析方法
        
        用于非异步环境
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
    使用 ReAct Agent 的二次审查器
    
    替代原有的固定策略 RAG 审查
    """
    
    def __init__(
        self,
        log_file: str,
        pre_binary_name: str,
        post_binary_name: str,
        pre_pseudo_file: str,
        post_pseudo_file: str,
        model_name: str = "GPT",
        max_iterations: int = 50,
        send_message: Optional[Callable] = None,
        history_dir: Optional[str] = None
    ):
        """
        初始化二次审查器
        
        Args:
            log_file: 日志文件路径
            pre_binary_name: 补丁前二进制名称
            post_binary_name: 补丁后二进制名称
            pre_pseudo_file: 补丁前伪代码文件
            post_pseudo_file: 补丁后伪代码文件
            model_name: 模型名称
            max_iterations: 最大迭代次数
            send_message: 消息发送回调
            history_dir: 历史目录
        """
        self.log_file = log_file
        self.context_log = f"{log_file}.react_ctx"
        self.pre_binary_name = pre_binary_name
        self.post_binary_name = post_binary_name
        self.pre_pseudo_file = pre_pseudo_file
        self.post_pseudo_file = post_pseudo_file
        self.model_name = model_name
        self.max_iterations = max_iterations
        self.send_message = send_message
        self.history_dir = history_dir
        
        # 创建 Agent
        self.agent = VulnReActAgent(
            pre_pseudo_file=pre_pseudo_file,
            post_pseudo_file=post_pseudo_file,
            pre_binary_name=pre_binary_name,
            post_binary_name=post_binary_name,
            model_name=model_name,
            max_iterations=max_iterations,
            send_message=send_message,
            history_dir=history_dir
        )
        
        # 任务缓存
        self._task_cache: Dict[str, Any] = {}
        
        logger.info("VulnReActRefiner 初始化完成")
    
    async def refine(
        self,
        fa: str,
        fb: str,
        cve_details: str = "",
        cwe: str = "",
        work_mode: str = "reproduction"
    ) -> str:
        """
        执行二次审查
        
        Args:
            fa: 补丁前函数文件路径
            fb: 补丁后函数文件路径
            cve_details: CVE 详情
            cwe: CWE 类型
            work_mode: 工作模式
            
        Returns:
            分析结果字符串
        """
        # 检查缓存
        cache_key = f"{os.path.basename(fa)}_{os.path.basename(fb)}"
        if cache_key in self._task_cache:
            logger.info(f"从缓存获取 {cache_key} 的分析结果")
            return self._task_cache[cache_key]
        
        # 读取代码内容
        try:
            with open(fa, 'r', encoding='utf-8') as f:
                code_before = f.read()
            with open(fb, 'r', encoding='utf-8') as f:
                code_after = f.read()
        except Exception as e:
            logger.error(f"读取函数文件失败: {e}")
            return f"读取函数文件失败: {str(e)}"
        
        # 提取函数名
        pre_function_name = os.path.basename(fa).split('.')[0]
        post_function_name = os.path.basename(fb).split('.')[0]
        function_name = pre_function_name
        
        # 发送开始消息
        if self.send_message:
            await self.send_message(
                f"🔍 开始 ReAct 智能分析: {function_name}",
                message_type="message",
                agent="Detection Agent"
            )
        
        # 执行分析
        result = await self.agent.analyze(
            function_name=function_name,
            code_before=code_before,
            code_after=code_after,
            vulnerability_type=cwe or "Unknown",
            cve_details=cve_details,
            cwe_id=cwe,
            pre_function_name=pre_function_name,
            post_function_name=post_function_name
        )
        
        # 格式化结果
        result_str = json.dumps(result, indent=2, ensure_ascii=False)
        
        # 写入日志
        try:
            with open(self.log_file, 'a', encoding='utf-8') as w:
                w.write(f"=== {os.path.basename(fa)} vs {os.path.basename(fb)} (ReAct分析) ===\n")
                w.write(result_str + "\n\n")
            
            # 写入推理链上下文
            with open(self.context_log, 'a', encoding='utf-8') as w:
                w.write(f"=== {os.path.basename(fa)} vs {os.path.basename(fb)} ===\n")
                w.write("Reasoning Chain:\n")
                for step in result.get("reasoning_chain", []):
                    w.write(f"  Tool: {step.get('tool')}\n")
                    w.write(f"  Input: {step.get('input')}\n")
                    w.write(f"  Output: {step.get('output')}\n\n")
                w.write("\n")
                
        except Exception as e:
            logger.error(f"写入日志失败: {e}")
        
        # 缓存结果
        self._task_cache[cache_key] = result_str
        
        # 发送完成消息
        if self.send_message:
            vuln_found = result.get("vulnerability_found", "Unknown")
            severity = result.get("severity", "Unknown")
            await self.send_message(
                f"✅ ReAct 分析完成: {function_name}\n"
                f"   漏洞发现: {vuln_found}, 严重性: {severity}",
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
    model_name: str = "GPT"
) -> str:
    """
    使用 ReAct Agent 分析函数对
    
    便捷函数，用于单次分析
    
    Args:
        fa: 补丁前函数文件路径
        fb: 补丁后函数文件路径
        pre_pseudo_file: 补丁前伪代码文件
        post_pseudo_file: 补丁后伪代码文件
        pre_binary_name: 补丁前二进制名
        post_binary_name: 补丁后二进制名
        cve_details: CVE 详情
        cwe: CWE 类型
        send_message: 消息发送回调
        model_name: 模型配置名称（对应 config.ini 中的 LLM.{model_name} 节）
        
    Returns:
        分析结果 JSON 字符串
    """
    agent = VulnReActAgent(
        pre_pseudo_file=pre_pseudo_file,
        post_pseudo_file=post_pseudo_file,
        pre_binary_name=pre_binary_name,
        post_binary_name=post_binary_name,
        model_name=model_name,
        send_message=send_message
    )
    
    # 读取代码
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
