# -*- coding: utf-8 -*-
"""
LangChain Tools for Vulnerability Analysis ReAct Agent

定义用于漏洞分析的工具集，供 ReAct Agent 调用
"""
import os
import re
import json
import asyncio
from typing import Optional, Type, Dict, Any, List
from pathlib import Path

from langchain.tools import BaseTool
from langchain.callbacks.manager import CallbackManagerForToolRun, AsyncCallbackManagerForToolRun
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from log import logger


class FunctionBodyInput(BaseModel):
    """获取函数体的输入参数"""
    function_name: str = Field(description="The name of the function to retrieve")
    version: str = Field(default="pre", description="Which version to get: 'pre' (before patch) or 'post' (after patch)")


class CallersInput(BaseModel):
    """获取调用者的输入参数"""
    function_name: str = Field(description="The name of the function to find callers for")
    depth: int = Field(default=2, description="Maximum recursion depth for finding callers (1-5)")
    version: str = Field(default="pre", description="Which version to analyze: 'pre' or 'post'")


class CalleesInput(BaseModel):
    """获取被调用函数的输入参数"""
    function_name: str = Field(description="The name of the function to find callees for")
    depth: int = Field(default=2, description="Maximum recursion depth for finding callees (1-5)")
    version: str = Field(default="pre", description="Which version to analyze: 'pre' or 'post'")


class DataFlowInput(BaseModel):
    """获取数据流的输入参数"""
    function_name: str = Field(description="The name of the function to analyze")
    variable_name: Optional[str] = Field(default=None, description="Optional: specific variable to trace")
    version: str = Field(default="pre", description="Which version to analyze: 'pre' or 'post'")


class SinkSliceInput(BaseModel):
    function_name: str = Field(description="The name of the function containing the sink")
    sink_expression: Optional[str] = Field(default=None, description="Concrete sink expression such as strcpy(v38, a2)")
    sink_name: Optional[str] = Field(default=None, description="Sink function name such as strcpy or system")
    sink_line_hint: Optional[str] = Field(default=None, description="Optional location hint for the sink")
    variable_name: Optional[str] = Field(default=None, description="Optional focus variable related to the sink")
    emit_slice_code: bool = Field(default=False, description="Whether to emit a conservative sliced code snippet")
    version: str = Field(default="pre", description="Which version to analyze: 'pre' or 'post'")


class AnalysisResultInput(BaseModel):
    """提交分析结果的输入参数"""
    vulnerability_found: str = Field(description="Whether a vulnerability was found: 'Yes' or 'No'")
    scenario_match: str = Field(default="Unknown", description="Whether the vulnerable scenario exists in the before version: 'Yes' or 'No'")
    property_match: str = Field(default="Unknown", description="Whether the after version removes the scenario/property: 'Yes', 'No', or 'Partial'")
    vulnerability_type: str = Field(default="Unknown", description="The CWE type of the vulnerability (e.g., 'CWE-78')")
    severity: str = Field(default="Unknown", description="Severity level: 'High', 'Medium', 'Low', or 'None'")
    vulnerable_code_location: str = Field(default="Not analyzed", description="Where the vulnerable operation exists in the current function")
    attack_vector: str = Field(default="See reasoning for details", description="How this issue could be exploited")
    impact: str = Field(default="Unknown", description="What is the potential impact")
    is_fixed: str = Field(default="Unknown", description="Whether the vulnerability is fixed in the patched version: 'Yes', 'No', or 'Partial'")
    data_flow_trace: str = Field(default="Not analyzed", description="Concrete `->` propagation chain for the current function using exact names where possible; prefer the longest evidence-supported chain and avoid vague summaries")
    dangerous_operations: str = Field(default="Not analyzed", description="Dangerous operations found in the current function")
    input_sources: str = Field(default="Not analyzed", description="Where controllable input enters the current function")
    confidence: str = Field(default="Low", description="Function-level analysis confidence: 'High', 'Medium', or 'Low'")
    root_cause: str = Field(default="Not analyzed", description="Detailed explanation of the vulnerability's root cause")
    fix_description: str = Field(default="Not analyzed", description="How the patch addresses the vulnerability")
    reason: List[str] = Field(default_factory=list, description="List of detailed reasoning points supporting the conclusion")


class PseudoCodeIndex:
    """
    伪代码索引类
    
    从已导出的伪C代码文件中构建函数索引，支持快速查找函数
    """
    
    # 函数头部的正则匹配模式
    FUNC_HEADER_PATTERN = re.compile(
        r'/\*{50,}\s*\*\s*函数:\s*(\S+)\s+\(地址:\s*(0x[0-9A-Fa-f]+)\)\s*\*{50,}/',
        re.DOTALL
    )
    
    def __init__(self, pseudo_file: str):
        """
        初始化伪代码索引
        
        Args:
            pseudo_file: 伪C代码文件路径
        """
        self.pseudo_file = pseudo_file
        self.functions: Dict[str, Dict[str, Any]] = {}
        self._lines: List[str] = []
        self._build_index()
    
    def _build_index(self):
        """构建函数索引"""
        if not os.path.exists(self.pseudo_file):
            logger.warning(f"伪代码文件不存在: {self.pseudo_file}")
            return
        
        try:
            with open(self.pseudo_file, 'r', encoding='utf-8', errors='replace') as f:
                self._lines = f.readlines()
        except Exception as e:
            logger.error(f"读取伪代码文件失败: {e}")
            return
        
        # 解析函数边界
        current_func = None
        func_start_line = 0
        
        for i, line in enumerate(self._lines):
            # 检测函数头部注释
            if '函数:' in line and '地址:' in line:
                # 保存前一个函数
                if current_func:
                    self.functions[current_func['name']] = {
                        'name': current_func['name'],
                        'address': current_func.get('address', ''),
                        'start_line': func_start_line,
                        'end_line': i - 1
                    }
                
                # 解析新函数
                match = re.search(r'函数:\s*(\S+)\s+\(地址:\s*(0x[0-9A-Fa-f]+)\)', line)
                if match:
                    current_func = {
                        'name': match.group(1),
                        'address': match.group(2)
                    }
                    func_start_line = i
        
        # 保存最后一个函数
        if current_func:
            self.functions[current_func['name']] = {
                'name': current_func['name'],
                'address': current_func.get('address', ''),
                'start_line': func_start_line,
                'end_line': len(self._lines) - 1
            }
        
        logger.info(f"索引构建完成: {len(self.functions)} 个函数")
    
    def get_function(self, func_name: str) -> Optional[str]:
        """
        获取指定函数的代码
        
        Args:
            func_name: 函数名
            
        Returns:
            函数代码字符串，如果未找到返回 None
        """
        if func_name not in self.functions:
            # 尝试模糊匹配
            for name in self.functions:
                if func_name in name or name in func_name:
                    func_name = name
                    break
            else:
                return None
        
        func_info = self.functions[func_name]
        start = func_info['start_line']
        end = func_info['end_line']
        
        return ''.join(self._lines[start:end + 1])
    
    def get_function_list(self) -> List[str]:
        """获取所有函数名列表"""
        return list(self.functions.keys())
    
    def search_functions(self, pattern: str) -> List[str]:
        """搜索匹配模式的函数名"""
        regex = re.compile(pattern, re.IGNORECASE)
        return [name for name in self.functions if regex.search(name)]


class VulnToolContext:
    """
    漏洞分析工具的上下文管理器

    管理伪代码索引、IDA服务连接等共享资源
    """

    def __init__(
        self,
        pre_pseudo_file: str,
        post_pseudo_file: str,
        pre_binary_name: str,
        post_binary_name: str,
        ida_service_url: str = "http://10.12.189.21:5000",
        history_dir: Optional[str] = None,
        llm: Optional[Any] = None
    ):
        """
        初始化工具上下文
        
        Args:
            pre_pseudo_file: 补丁前的伪代码文件路径
            post_pseudo_file: 补丁后的伪代码文件路径
            pre_binary_name: 补丁前二进制名称
            post_binary_name: 补丁后二进制名称
            ida_service_url: IDA 服务地址
            history_dir: 历史记录目录
        """
        self.pre_pseudo_file = pre_pseudo_file
        self.post_pseudo_file = post_pseudo_file
        self.pre_binary_name = pre_binary_name
        self.post_binary_name = post_binary_name
        self.ida_service_url = ida_service_url
        self.history_dir = history_dir
        self.llm = llm  # 用于 LLM-based 数据流分析
        # 构建伪代码索引
        self.pre_index = PseudoCodeIndex(pre_pseudo_file) if pre_pseudo_file else None
        self.post_index = PseudoCodeIndex(post_pseudo_file) if post_pseudo_file else None
        
        # 缓存
        self._call_info_cache: Dict[str, Any] = {}
        
        # 推理链记录
        self.reasoning_chain: List[Dict[str, Any]] = []
        self.current_function_name: str = ""
        self.current_cve_details: str = ""
        self.current_cwe_id: str = ""
    
    def get_index(self, version: str) -> Optional[PseudoCodeIndex]:
        """获取指定版本的伪代码索引"""
        return self.pre_index if version == "pre" else self.post_index
    
    def get_binary_name(self, version: str) -> str:
        """获取指定版本的二进制名称"""
        return self.pre_binary_name if version == "pre" else self.post_binary_name
    
    def add_reasoning_step(self, tool: str, input_data: Any, output: str):
        """记录推理步骤"""
        self.reasoning_chain.append({
            "tool": tool,
            "input": input_data,
            "output": output[:500] + "..." if len(output) > 500 else output
        })
    
    def get_reasoning_summary(self) -> str:
        """获取推理链摘要"""
        if not self.reasoning_chain:
            return "No tools were used."
        
        summary = []
        for i, step in enumerate(self.reasoning_chain, 1):
            summary.append(f"{i}. [{step['tool']}] Input: {step['input']}")
            summary.append(f"   Output: {step['output']}")
        
        return "\n".join(summary)


# 全局工具上下文（在创建工具时设置）
_tool_context: Optional[VulnToolContext] = None


def _extract_json_payload(raw_value: Any) -> Optional[Dict[str, Any]]:
    """Best-effort extract a JSON object from a raw tool input string."""
    if raw_value is None:
        return None
    text = raw_value if isinstance(raw_value, str) else str(raw_value)
    stripped = text.strip()
    candidates: List[str] = []
    if stripped.startswith("{") and stripped.endswith("}"):
        candidates.append(stripped)

    start = stripped.find("{")
    end = stripped.rfind("}")
    if start != -1 and end > start:
        candidate = stripped[start:end + 1]
        if candidate not in candidates:
            candidates.append(candidate)

    for candidate in candidates:
        try:
            payload = json.loads(candidate)
            if isinstance(payload, dict):
                return payload
        except json.JSONDecodeError:
            continue
    return None


def set_tool_context(context: VulnToolContext):
    """设置全局工具上下文"""
    global _tool_context
    _tool_context = context


def get_tool_context() -> Optional[VulnToolContext]:
    """获取全局工具上下文"""
    return _tool_context


def _normalize_tool_inputs(
    function_name: str,
    version: Optional[str] = None,
    variable_name: Optional[str] = None,
    depth: Optional[int] = None
):
    """兼容解析被错误包裹为 JSON 字符串的工具输入"""
    payload = _extract_json_payload(function_name)
    if payload:
        function_name = payload.get("function_name", function_name)
        variable_name = payload.get("variable_name", variable_name)
        version = payload.get("version", version)
        depth = payload.get("depth", depth)

    function_name = str(function_name or "").strip()
    if function_name in {"", "{}", "null", "none"}:
        function_name = ""

    if variable_name is not None:
        variable_name = str(variable_name).strip() or None

    if version is not None:
        version = str(version).strip().lower()
        if version not in {"pre", "post"}:
            version = None

    if depth is not None:
        if isinstance(depth, str):
            stripped_depth = depth.strip()
            try:
                depth = int(stripped_depth)
            except ValueError:
                depth = None
        else:
            try:
                depth = int(depth)
            except (TypeError, ValueError):
                depth = None

    return function_name, version, variable_name, depth


class GetFunctionBodyTool(BaseTool):
    """获取函数体代码的工具"""
    
    name: str = "get_function_body"
    description: str = """Retrieve the complete pseudo-C code of a specific function from the binary.

Use this tool when you need to:
- Understand what a called function does
- Examine a function's implementation details
- Check how a function handles its parameters

Input should be a JSON with:
- function_name: The name of the function to retrieve
- version: 'pre' (before patch) or 'post' (after patch), default is 'pre'"""
    args_schema: Type[BaseModel] = FunctionBodyInput
    
    def _run(
        self,
        function_name: str,
        version: str = "pre",
        run_manager: Optional[CallbackManagerForToolRun] = None
    ) -> str:
        """同步执行"""
        function_name, version, _, _ = _normalize_tool_inputs(function_name, version=version)
        version = version or "pre"
        if not function_name:
            return "Error: Missing required field 'function_name'"
        context = get_tool_context()
        if not context:
            return "Error: Tool context not initialized"
        
        index = context.get_index(version)
        if not index:
            return f"Error: No pseudo-code index available for version '{version}'"
        
        code = index.get_function(function_name)
        if code:
            result = f"[Function: {function_name}] ({version} version)\n{code}"
            context.add_reasoning_step(self.name, {"function_name": function_name, "version": version}, result)
            return result
        
        # 尝试搜索类似函数
        similar = index.search_functions(function_name)
        if similar:
            return f"Function '{function_name}' not found. Similar functions: {', '.join(similar[:5])}"
        
        return f"Function '{function_name}' not found in {version} version"
    
    async def _arun(
        self,
        function_name: str,
        version: str = "pre",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None
    ) -> str:
        """异步执行"""
        return self._run(function_name, version)


class GetCallersTool(BaseTool):
    """获取函数调用者的工具"""
    
    name: str = "get_callers"
    description: str = """Get all functions that call a specific function (upstream analysis).

Use this tool when you need to:
- Understand how a function is called
- Trace where function parameters come from
- Determine if user input can reach a function

Input should be a JSON with:
- function_name: The name of the function to find callers for
- depth: Maximum recursion depth (1-5), default is 2
- version: 'pre' or 'post', default is 'pre'"""
    args_schema: Type[BaseModel] = CallersInput
    
    def _run(
        self,
        function_name: str,
        depth: int = 2,
        version: str = "pre",
        run_manager: Optional[CallbackManagerForToolRun] = None
    ) -> str:
        """同步执行"""
        function_name, version, _, depth = _normalize_tool_inputs(
            function_name,
            version=version,
            depth=depth
        )
        version = version or "pre"
        depth = depth or 2
        if not function_name:
            return "Error: Missing required field 'function_name'"
        context = get_tool_context()
        if not context:
            return "Error: Tool context not initialized"
        
        # 限制深度
        depth = min(max(depth, 1), 5)
        
        index = context.get_index(version)
        if not index:
            return f"Error: No pseudo-code index available for version '{version}'"
        
        # 通过搜索伪代码文件来查找调用者
        callers = self._find_callers_in_pseudo(index, function_name, depth)
        
        if callers:
            result = f"[Callers of {function_name}] ({version} version, depth={depth})\n"
            for caller_info in callers:
                result += f"\n- {caller_info['name']}:\n"
                for call_ctx in caller_info.get('contexts', []):
                    result += f"  Call context: {call_ctx}\n"
            
            context.add_reasoning_step(
                self.name, 
                {"function_name": function_name, "depth": depth, "version": version},
                result
            )
            return result
        
        return f"No callers found for function '{function_name}' in {version} version"
    
    def _find_callers_in_pseudo(
        self, 
        index: PseudoCodeIndex, 
        target_func: str, 
        depth: int
    ) -> List[Dict[str, Any]]:
        """在伪代码中搜索调用目标函数的函数"""
        callers = []
        call_pattern = re.compile(rf'\b{re.escape(target_func)}\s*\(')
        
        for func_name in index.get_function_list():
            if func_name == target_func:
                continue
            
            code = index.get_function(func_name)
            if not code:
                continue
            
            matches = call_pattern.findall(code)
            if matches:
                # 提取调用上下文
                contexts = []
                for line in code.split('\n'):
                    if call_pattern.search(line):
                        contexts.append(line.strip()[:100])
                
                callers.append({
                    'name': func_name,
                    'call_count': len(matches),
                    'contexts': contexts[:3]  # 最多3个上下文
                })
        
        return callers[:10]  # 最多返回10个调用者
    
    async def _arun(
        self,
        function_name: str,
        depth: int = 2,
        version: str = "pre",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None
    ) -> str:
        """异步执行"""
        return self._run(function_name, depth, version)


class GetCalleesTool(BaseTool):
    """获取函数调用的其他函数的工具"""
    
    name: str = "get_callees"
    description: str = """Get all functions called by a specific function (downstream analysis).

Use this tool when you need to:
- Understand what a function does internally
- Find dangerous operations within a function
- Trace data flow to dangerous sinks

Input should be a JSON with:
- function_name: The name of the function to find callees for
- depth: Maximum recursion depth (1-5), default is 2
- version: 'pre' or 'post', default is 'pre'"""
    args_schema: Type[BaseModel] = CalleesInput
    
    def _run(
        self,
        function_name: str,
        depth: int = 2,
        version: str = "pre",
        run_manager: Optional[CallbackManagerForToolRun] = None
    ) -> str:
        """同步执行"""
        function_name, version, _, depth = _normalize_tool_inputs(
            function_name,
            version=version,
            depth=depth
        )
        version = version or "pre"
        depth = depth or 2
        if not function_name:
            return "Error: Missing required field 'function_name'"
        context = get_tool_context()
        if not context:
            return "Error: Tool context not initialized"
        
        depth = min(max(depth, 1), 5)
        
        index = context.get_index(version)
        if not index:
            return f"Error: No pseudo-code index available for version '{version}'"
        
        code = index.get_function(function_name)
        if not code:
            return f"Function '{function_name}' not found in {version} version"
        
        # 提取函数调用
        callees = self._extract_callees(code, index)
        
        if callees:
            result = f"[Callees of {function_name}] ({version} version)\n"
            for callee in callees:
                result += f"\n- {callee['name']}"
                if callee.get('is_dangerous'):
                    result += " [DANGEROUS]"
                if callee.get('contexts'):
                    result += f":\n  {callee['contexts'][0]}"
            
            context.add_reasoning_step(
                self.name,
                {"function_name": function_name, "depth": depth, "version": version},
                result
            )
            return result
        
        return f"No function calls found in '{function_name}'"
    
    def _extract_callees(
        self, 
        code: str, 
        index: PseudoCodeIndex
    ) -> List[Dict[str, Any]]:
        """从代码中提取被调用的函数"""
        # 危险函数列表
        dangerous_funcs = {
            'system', 'popen', 'execl', 'execv', 'execve', 'exec',
            'strcpy', 'strncpy', 'sprintf', 'vsprintf', 'gets',
            'memcpy', 'memmove', 'strcat', 'strncat',
            'scanf', 'fscanf', 'sscanf'
        }
        
        # 匹配函数调用
        call_pattern = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(')
        
        callees = {}
        for line in code.split('\n'):
            for match in call_pattern.finditer(line):
                func_name = match.group(1)
                
                # 跳过关键字
                if func_name in {'if', 'while', 'for', 'switch', 'return', 'sizeof'}:
                    continue
                
                if func_name not in callees:
                    callees[func_name] = {
                        'name': func_name,
                        'is_dangerous': func_name.lower() in dangerous_funcs,
                        'contexts': [],
                        'count': 0
                    }
                
                callees[func_name]['count'] += 1
                if len(callees[func_name]['contexts']) < 2:
                    callees[func_name]['contexts'].append(line.strip()[:100])
        
        # 排序：危险函数优先
        result = sorted(
            callees.values(),
            key=lambda x: (not x['is_dangerous'], -x['count'])
        )
        
        return result[:15]
    
    async def _arun(
        self,
        function_name: str,
        depth: int = 2,
        version: str = "pre",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None
    ) -> str:
        """异步执行"""
        return self._run(function_name, depth, version)


_DATA_FLOW_PROMPT = """You are a binary vulnerability analyst. Analyze the data flow of the following IDA-decompiled pseudo-C function.

Function name: {function_name}
Version: {version}
{variable_focus}

Function code:
```c
{code}
```

Analyze and report:
1. **Parameter roles**: For each function parameter, identify its semantic role:
   - Is it an output buffer (written to)?
   - Is it an input source (read from, potentially attacker-controlled)?
   - Is it a size/length limit?
   - Is it a flag/mode?

2. **Data flow paths**: Trace how data flows through the function:
   - What are the sources of data (parameters, global vars, return values from calls)?
   - What are the sinks (where data is written, passed to other functions, or used in operations)?
   - Are there any bounds checks? If so, are they correct?
   - Build the longest concrete propagation chains you can support from the code using `->`
   - Use exact names for functions, parameters, locals, globals, structure fields, pointer offsets, and sink calls whenever available
   - Do NOT collapse concrete chains into vague summaries like "memory operations" or "index calculations"
   - If only part of the chain is known, keep the concrete partial chain instead of inventing unsupported hops

3. **Potential attack surface**: Based on the parameter roles and data flow:
   - Which parameters could carry attacker-controlled data?
   - Does attacker-controlled data reach any dangerous operations without proper validation?
   - Are there any logic bugs in bounds checking (e.g., wrong counter used for bounds check)?

{variable_section}

Be specific about variable names and line-level observations. Do not speculate beyond what the code shows."""


_SINK_SLICE_PROMPT = """You are a static-analysis assistant specialized in sink-anchored backward slicing for vulnerability analysis.

Analyze ONE specified sink inside ONE decompiled pseudo-C function.

Function name: {function_name}
Version: {version}
Target sink expression: {sink_expression}
Target sink name: {sink_name}
Optional sink line hint: {sink_line_hint}
Optional focus variable: {variable_name}

Function code:
```c
{code}
```

Rules:
1. Treat the specified sink as the only slicing anchor.
2. Work backward from the sink and keep only data/control dependencies relevant to that sink.
3. Use exact local names and exact conditions when available.
4. Ignore unrelated sinks and unrelated branches.
5. If the full source is not visible inside this function, stop at the parameter/local boundary and state the cross-function gap explicitly.
6. Be conservative: over-approximation is acceptable; missing required dependencies is not.

Output ONLY valid JSON in this format:
{{
  "sink": "...",
  "sink_kind": "...",
  "tracked_vars": ["..."],
  "source_candidates": ["..."],
  "control_dependencies": ["..."],
  "local_data_flow_trace": "...",
  "slice_summary": "...",
  "cross_function_gap": "...",
  "next_recommended_actions": ["..."],
  "confidence": "High/Medium/Low"{slice_code_clause}
}}"""


class GetDataFlowTool(BaseTool):
    """获取数据流分析的工具（LLM-based）"""
    name: str = "get_data_flow"
    description: str = """Get LLM-based semantic data flow analysis for a specific function or variable.

Use this tool when you need to:
- Understand the semantic role of each function parameter (input buffer, output buffer, size limit, etc.)
- Trace how data flows through the function from sources to sinks
- Determine if attacker-controlled data can reach dangerous operations
- Identify logic bugs in bounds checking or validation
- Recover concrete propagation chains that can later be copied into `data_flow_trace`

Input should be a JSON with:
- function_name: The name of the function to analyze
- variable_name: (Optional) specific variable to focus the analysis on
- version: 'pre' or 'post', default is 'pre'"""
    args_schema: Type[BaseModel] = DataFlowInput
    def _run(
        self,
        function_name: str,
        variable_name: Optional[str] = None,
        version: str = "pre",
        run_manager: Optional[CallbackManagerForToolRun] = None
    ) -> str:
        function_name, version, variable_name, _ = _normalize_tool_inputs(
            function_name, version=version, variable_name=variable_name
        )
        version = version or "pre"
        if not function_name:
            return "Error: Missing required field 'function_name'"
        context = get_tool_context()
        if not context:
            return "Error: Tool context not initialized"
        index = context.get_index(version)
        if not index:
            return f"Error: No pseudo-code index available for version '{version}'"
        code = index.get_function(function_name)
        if not code:
            return f"Function '{function_name}' not found in {version} version"

        if not context.llm:
            return f"Error: LLM not available in tool context for data flow analysis of '{function_name}'"

        variable_focus = f"Focus variable: {variable_name}" if variable_name else ""
        variable_section = (
            f"\n4. **Variable trace for '{variable_name}'**: Track every assignment to and use of "
            f"'{variable_name}', and determine whether its value can be influenced by external input."
            if variable_name else ""
        )

        prompt = _DATA_FLOW_PROMPT.format(
            function_name=function_name,
            version=version,
            code=code[:6000],  # 截断过长代码
            variable_focus=variable_focus,
            variable_section=variable_section,
        )

        try:
            from langchain.schema import HumanMessage
            response = context.llm.invoke([HumanMessage(content=prompt)])
            analysis_text = response.content if hasattr(response, "content") else str(response)
        except Exception as e:
            logger.error(f"LLM data flow analysis failed for {function_name}: {e}")
            return f"Data flow analysis failed for '{function_name}': {e}"

        result = f"[Data Flow Analysis: {function_name}] ({version} version)\n{analysis_text}"
        context.add_reasoning_step(
            self.name,
            {"function_name": function_name, "variable_name": variable_name, "version": version},
            result
        )
        return result
    async def _arun(
        self,
        function_name: str,
        variable_name: Optional[str] = None,
        version: str = "pre",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None
    ) -> str:
        return self._run(function_name, variable_name, version)


class GetSinkSliceTool(BaseTool):
    """Sink-anchored backward slicing tool."""

    name: str = "get_sink_slice"
    description: str = """Get a sink-anchored backward slice for one suspicious sink in the current function.

Use this tool after get_data_flow has identified a concrete suspicious sink.

Input should be a JSON with:
- function_name: current function name
- sink_expression: concrete sink expression when available
- sink_name: sink API name such as strcpy/system/memcpy
- sink_line_hint: optional location hint
- variable_name: optional focus variable
- emit_slice_code: optional bool, default false
- version: 'pre' or 'post', default is 'pre'

Output: JSON describing tracked vars, local data-flow trace, control dependencies, and cross-function gaps."""
    args_schema: Type[BaseModel] = SinkSliceInput

    def _run(
        self,
        function_name: str,
        sink_expression: Optional[str] = None,
        sink_name: Optional[str] = None,
        sink_line_hint: Optional[str] = None,
        variable_name: Optional[str] = None,
        emit_slice_code: bool = False,
        version: str = "pre",
        run_manager: Optional[CallbackManagerForToolRun] = None
    ) -> str:
        payload = _extract_json_payload(function_name)
        if payload:
            function_name = payload.get("function_name", function_name)
            sink_expression = payload.get("sink_expression", sink_expression)
            sink_name = payload.get("sink_name", sink_name)
            sink_line_hint = payload.get("sink_line_hint", sink_line_hint)
            variable_name = payload.get("variable_name", variable_name)
            emit_slice_code = payload.get("emit_slice_code", emit_slice_code)
            version = payload.get("version", version)

        function_name, version, variable_name, _ = _normalize_tool_inputs(
            function_name, version=version, variable_name=variable_name
        )
        if isinstance(emit_slice_code, str):
            emit_slice_code = str(emit_slice_code).strip().lower() in {"1", "true", "yes", "y"}
        version = version or "pre"
        if not function_name:
            return "Error: Missing required field 'function_name'"
        if not (sink_expression or sink_name):
            return "Error: At least one of 'sink_expression' or 'sink_name' is required"

        context = get_tool_context()
        if not context:
            return "Error: Tool context not initialized"

        index = context.get_index(version)
        if not index:
            return f"Error: No pseudo-code index available for version '{version}'"

        code = index.get_function(function_name)
        if not code:
            return f"Function '{function_name}' not found in {version} version"

        if not context.llm:
            return f"Error: LLM not available in tool context for sink slicing of '{function_name}'"

        sink_expression = str(sink_expression or "").strip() or "Not provided"
        sink_name = str(sink_name or "").strip() or "Not provided"
        sink_line_hint = str(sink_line_hint or "").strip() or "Not provided"
        variable_name = variable_name or "Not provided"
        slice_code_clause = ',\n  "slice_code": "..."' if emit_slice_code else ""

        prompt = _SINK_SLICE_PROMPT.format(
            function_name=function_name,
            version=version,
            sink_expression=sink_expression,
            sink_name=sink_name,
            sink_line_hint=sink_line_hint,
            variable_name=variable_name,
            code=code[:6000],
            slice_code_clause=slice_code_clause,
        )

        try:
            from langchain.schema import HumanMessage
            response = context.llm.invoke([HumanMessage(content=prompt)])
            analysis_text = response.content if hasattr(response, "content") else str(response)
        except Exception as e:
            logger.error(f"LLM sink slicing failed for {function_name}: {e}")
            return f"Sink slicing failed for '{function_name}': {e}"

        result = f"[Sink Slice: {function_name}] ({version} version)\n{analysis_text}"
        context.add_reasoning_step(
            self.name,
            {
                "function_name": function_name,
                "sink_expression": sink_expression,
                "sink_name": sink_name,
                "sink_line_hint": sink_line_hint,
                "variable_name": variable_name,
                "emit_slice_code": emit_slice_code,
                "version": version,
            },
            result
        )
        return result

    async def _arun(
        self,
        function_name: str,
        sink_expression: Optional[str] = None,
        sink_name: Optional[str] = None,
        sink_line_hint: Optional[str] = None,
        variable_name: Optional[str] = None,
        emit_slice_code: bool = False,
        version: str = "pre",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None
    ) -> str:
        return self._run(
            function_name=function_name,
            sink_expression=sink_expression,
            sink_name=sink_name,
            sink_line_hint=sink_line_hint,
            variable_name=variable_name,
            emit_slice_code=emit_slice_code,
            version=version
        )


class SubmitAnalysisTool(BaseTool):
    """提交最终分析结果的工具"""
    
    name: str = "submit_analysis"
    description: str = """Submit your final vulnerability analysis.

Use this tool ONLY when you have gathered sufficient information to make a confident assessment.

Input should be a JSON with:
- vulnerability_found: 'Yes' or 'No'
- scenario_match: 'Yes' or 'No'
- property_match: 'Yes', 'No', or 'Partial'
- vulnerability_type: CWE ID (e.g., 'CWE-78')
- If the observed evidence more strongly matches a different bug class than the requested CWE, set scenario_match to 'No' instead of forcing the requested CWE
- severity: 'High', 'Medium', 'Low', or 'None'
- vulnerable_code_location: where the vulnerable operation exists in the current function
- attack_vector: how exploitation would occur
- impact: potential impact
- is_fixed: 'Yes', 'No', or 'Partial'
- data_flow_trace: key current-function data flow paths identified, written as a concrete `->` propagation chain with exact names where possible
- If `get_sink_slice` was used, prefer its `local_data_flow_trace` as the core of `data_flow_trace`
- Only prepend caller-side provenance when it is directly supported by `get_callers` / `get_function_body` observations
- dangerous_operations: dangerous operations found in the current function
- input_sources: where controllable input enters the current function
- confidence: function-level confidence: 'High', 'Medium', or 'Low'
- root_cause: Detailed explanation of the vulnerability's root cause
- fix_description: How the patch addresses the vulnerability
- reason: List of reasoning points supporting your conclusion"""
    args_schema: Type[BaseModel] = AnalysisResultInput
    return_direct: bool = True  # 直接返回结果，结束 Agent 循环
    
    def _run(
        self,
        vulnerability_found: Optional[str] = None,
        scenario_match: Optional[str] = None,
        property_match: Optional[str] = None,
        vulnerability_type: Optional[str] = None,
        severity: Optional[str] = None,
        vulnerable_code_location: Optional[str] = None,
        attack_vector: Optional[str] = None,
        impact: Optional[str] = None,
        is_fixed: Optional[str] = None,
        data_flow_trace: Optional[str] = None,
        dangerous_operations: Optional[str] = None,
        input_sources: Optional[str] = None,
        confidence: Optional[str] = None,
        root_cause: Optional[str] = None,
        fix_description: Optional[str] = None,
        reason: Optional[List[str]] = None,
        run_manager: Optional[CallbackManagerForToolRun] = None,
        **kwargs
    ) -> str:
        """同步执行"""
        if isinstance(vulnerability_found, str) and vulnerability_type is None:
            stripped = vulnerability_found.strip()
            if stripped.startswith("{") and stripped.endswith("}"):
                try:
                    payload = json.loads(stripped)
                    vulnerability_details = payload.get("vulnerability_details") or {}
                    fix_analysis = payload.get("fix_analysis") or {}
                    evidence = payload.get("evidence") or {}
                    vulnerability_found = payload.get("vulnerability_found")
                    scenario_match = payload.get("scenario_match")
                    property_match = payload.get("property_match")
                    vulnerability_type = payload.get("vulnerability_type")
                    severity = payload.get("severity")
                    vulnerable_code_location = payload.get("vulnerable_code_location")
                    attack_vector = payload.get("attack_vector") or vulnerability_details.get("attack_vector")
                    impact = payload.get("impact") or vulnerability_details.get("impact")
                    is_fixed = payload.get("is_fixed") or fix_analysis.get("is_fixed")
                    data_flow_trace = payload.get("data_flow_trace") or evidence.get("data_flow_trace")
                    dangerous_operations = payload.get("dangerous_operations") or evidence.get("dangerous_operations")
                    input_sources = payload.get("input_sources") or evidence.get("input_sources")
                    confidence = payload.get("confidence")
                    root_cause = payload.get("root_cause") or vulnerability_details.get("root_cause")
                    fix_description = payload.get("fix_description") or fix_analysis.get("fix_description")
                    reason = payload.get("reason")
                except json.JSONDecodeError:
                    pass
        elif isinstance(vulnerability_found, dict):
            payload = vulnerability_found
            vulnerability_details = payload.get("vulnerability_details") or {}
            fix_analysis = payload.get("fix_analysis") or {}
            evidence = payload.get("evidence") or {}
            vulnerability_found = payload.get("vulnerability_found")
            scenario_match = payload.get("scenario_match")
            property_match = payload.get("property_match")
            vulnerability_type = payload.get("vulnerability_type")
            severity = payload.get("severity")
            vulnerable_code_location = payload.get("vulnerable_code_location")
            attack_vector = payload.get("attack_vector") or vulnerability_details.get("attack_vector")
            impact = payload.get("impact") or vulnerability_details.get("impact")
            is_fixed = payload.get("is_fixed") or fix_analysis.get("is_fixed")
            data_flow_trace = payload.get("data_flow_trace") or evidence.get("data_flow_trace")
            dangerous_operations = payload.get("dangerous_operations") or evidence.get("dangerous_operations")
            input_sources = payload.get("input_sources") or evidence.get("input_sources")
            confidence = payload.get("confidence")
            root_cause = payload.get("root_cause") or vulnerability_details.get("root_cause")
            fix_description = payload.get("fix_description") or fix_analysis.get("fix_description")
            reason = payload.get("reason")

        vulnerability_found = vulnerability_found or "Unknown"
        is_fixed = is_fixed or "Unknown"
        scenario_match = scenario_match or ("Yes" if vulnerability_found == "Yes" else "No")
        property_match = property_match or ("Yes" if is_fixed == "Yes" else "No")
        vulnerability_type = vulnerability_type or "Unknown"
        severity = severity or "Unknown"
        vulnerable_code_location = vulnerable_code_location or "Not analyzed"
        attack_vector = attack_vector or "See reasoning for details"
        impact = impact or (f"{severity} severity impact" if severity != "Unknown" else "Not analyzed")
        data_flow_trace = data_flow_trace or "Not analyzed"
        dangerous_operations = dangerous_operations or "Not analyzed"
        input_sources = input_sources or "Not analyzed"
        confidence = confidence or "Low"
        root_cause = root_cause or "Not analyzed"
        fix_description = fix_description or "Not analyzed"
        reason = reason or []

        context = get_tool_context()

        # 构建结果 JSON（CVE_Attribution 由 post-processing 填充）
        result = {
            "vulnerability_found": vulnerability_found,
            "scenario_match": scenario_match,
            "property_match": property_match,
            "Scenario_match & Property_match": "Yes" if (scenario_match == "Yes" and property_match == "Yes") else "No",
            "vulnerability_type": vulnerability_type,
            "severity": severity,
            "vulnerable_code_location": vulnerable_code_location,
            "vulnerability_details": {
                "root_cause": root_cause,
                "attack_vector": attack_vector,
                "impact": impact
            },
            "fix_analysis": {
                "is_fixed": is_fixed,
                "fix_description": fix_description
            },
            "evidence": {
                "data_flow_trace": data_flow_trace,
                "dangerous_operations": dangerous_operations,
                "input_sources": input_sources
            },
            "confidence": confidence,
            "reason": reason,
            "reasoning_chain": context.get_reasoning_summary() if context else "N/A",
        }

        return json.dumps(result, indent=2, ensure_ascii=False)
    
    async def _arun(
        self,
        vulnerability_found: Optional[str] = None,
        scenario_match: Optional[str] = None,
        property_match: Optional[str] = None,
        vulnerability_type: Optional[str] = None,
        severity: Optional[str] = None,
        vulnerable_code_location: Optional[str] = None,
        attack_vector: Optional[str] = None,
        impact: Optional[str] = None,
        is_fixed: Optional[str] = None,
        data_flow_trace: Optional[str] = None,
        dangerous_operations: Optional[str] = None,
        input_sources: Optional[str] = None,
        confidence: Optional[str] = None,
        root_cause: Optional[str] = None,
        fix_description: Optional[str] = None,
        reason: Optional[List[str]] = None,
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
        **kwargs
    ) -> str:
        """异步执行"""
        return self._run(
            vulnerability_found=vulnerability_found,
            scenario_match=scenario_match,
            property_match=property_match,
            vulnerability_type=vulnerability_type,
            severity=severity,
            vulnerable_code_location=vulnerable_code_location,
            attack_vector=attack_vector,
            impact=impact,
            is_fixed=is_fixed,
            data_flow_trace=data_flow_trace,
            dangerous_operations=dangerous_operations,
            input_sources=input_sources,
            confidence=confidence,
            root_cause=root_cause,
            fix_description=fix_description,
            reason=reason,
        )


def create_vuln_tools(context: VulnToolContext) -> List[BaseTool]:
    """
    创建漏洞分析工具集
    
    Args:
        context: 工具上下文
        
    Returns:
        工具列表
    """
    set_tool_context(context)
    
    return [
        GetFunctionBodyTool(),
        GetCallersTool(),
        GetCalleesTool(),
        GetDataFlowTool(),
        GetSinkSliceTool(),
        SubmitAnalysisTool()
    ]


__all__ = [
    'VulnToolContext',
    'PseudoCodeIndex',
    'create_vuln_tools',
    'set_tool_context',
    'get_tool_context',
    'GetFunctionBodyTool',
    'GetCallersTool',
    'GetCalleesTool',
    'GetDataFlowTool',
    'GetSinkSliceTool',
    'SubmitAnalysisTool'
]
