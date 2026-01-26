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


class AnalysisResultInput(BaseModel):
    """提交分析结果的输入参数"""
    vulnerability_found: str = Field(description="Whether a vulnerability was found: 'Yes' or 'No'")
    vulnerability_type: str = Field(default="Unknown", description="The CWE type of the vulnerability (e.g., 'CWE-78')")
    severity: str = Field(default="Unknown", description="Severity level: 'High', 'Medium', 'Low', or 'None'")
    is_fixed: str = Field(default="Unknown", description="Whether the vulnerability is fixed in the patched version: 'Yes', 'No', or 'Partial'")
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
        history_dir: Optional[str] = None
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
        
        # 构建伪代码索引
        self.pre_index = PseudoCodeIndex(pre_pseudo_file) if pre_pseudo_file else None
        self.post_index = PseudoCodeIndex(post_pseudo_file) if post_pseudo_file else None
        
        # 缓存
        self._call_info_cache: Dict[str, Any] = {}
        
        # 推理链记录
        self.reasoning_chain: List[Dict[str, Any]] = []
    
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
    if isinstance(function_name, str):
        stripped = function_name.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                payload = json.loads(stripped)
                function_name = payload.get("function_name", function_name)
                variable_name = payload.get("variable_name", variable_name)
                version = payload.get("version", version)
                depth = payload.get("depth", depth)
            except json.JSONDecodeError:
                pass

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


class GetDataFlowTool(BaseTool):
    """获取数据流分析的工具"""
    
    name: str = "get_data_flow"
    description: str = """Get data flow analysis for a specific function or variable.

Use this tool when you need to:
- Trace where a variable's value comes from
- Determine if a value is user-controllable
- Understand how data propagates through the function

Input should be a JSON with:
- function_name: The name of the function to analyze
- variable_name: (Optional) specific variable to trace
- version: 'pre' or 'post', default is 'pre'"""
    args_schema: Type[BaseModel] = DataFlowInput
    
    def _run(
        self,
        function_name: str,
        variable_name: Optional[str] = None,
        version: str = "pre",
        run_manager: Optional[CallbackManagerForToolRun] = None
    ) -> str:
        """同步执行"""
        function_name, version, variable_name, _ = _normalize_tool_inputs(
            function_name,
            version=version,
            variable_name=variable_name
        )
        version = version or "pre"
        context = get_tool_context()
        if not context:
            return "Error: Tool context not initialized"
        
        index = context.get_index(version)
        if not index:
            return f"Error: No pseudo-code index available for version '{version}'"
        
        code = index.get_function(function_name)
        if not code:
            return f"Function '{function_name}' not found in {version} version"
        
        # 执行简单的数据流分析
        analysis = self._analyze_data_flow(code, variable_name)
        
        result = f"[Data Flow Analysis: {function_name}] ({version} version)\n"
        
        if variable_name:
            result += f"Target variable: {variable_name}\n\n"
        
        # 输入源
        if analysis['input_sources']:
            result += "📥 Input Sources:\n"
            for src in analysis['input_sources']:
                result += f"  - {src}\n"
        
        # 危险操作
        if analysis['dangerous_sinks']:
            result += "\n⚠️ Dangerous Sinks:\n"
            for sink in analysis['dangerous_sinks']:
                result += f"  - {sink}\n"
        
        # 变量定义
        if variable_name and analysis['variable_defs']:
            result += f"\n📝 Definitions of '{variable_name}':\n"
            for defn in analysis['variable_defs']:
                result += f"  - {defn}\n"
        
        # 变量使用
        if variable_name and analysis['variable_uses']:
            result += f"\n📖 Uses of '{variable_name}':\n"
            for use in analysis['variable_uses']:
                result += f"  - {use}\n"
        
        context.add_reasoning_step(
            self.name,
            {"function_name": function_name, "variable_name": variable_name, "version": version},
            result
        )
        
        return result
    
    def _analyze_data_flow(
        self, 
        code: str, 
        target_var: Optional[str] = None
    ) -> Dict[str, List[str]]:
        """分析代码的数据流"""
        
        # 输入源模式
        input_patterns = {
            'HTTP Input': re.compile(r'\b(websGet|http_header|HTTP_|getenv|nvram_get|cgi_get)\s*\(', re.I),
            'Network Input': re.compile(r'\b(recv|read|recvfrom|socket_read)\s*\(', re.I),
            'File Input': re.compile(r'\b(fopen|fread|fgets|fscanf)\s*\(', re.I),
            'User Input': re.compile(r'\b(gets|scanf|getchar)\s*\(', re.I),
        }
        
        # 危险操作模式
        sink_patterns = {
            'Command Execution': re.compile(r'\b(system|popen|execl|execv|execve)\s*\(', re.I),
            'Buffer Operation': re.compile(r'\b(strcpy|strncpy|sprintf|memcpy|strcat)\s*\(', re.I),
            'Format String': re.compile(r'\b(printf|fprintf|sprintf|snprintf)\s*\([^,]+,\s*[a-zA-Z_]', re.I),
        }
        
        result = {
            'input_sources': [],
            'dangerous_sinks': [],
            'variable_defs': [],
            'variable_uses': []
        }
        
        lines = code.split('\n')
        
        for line in lines:
            line_stripped = line.strip()
            
            # 检查输入源
            for source_type, pattern in input_patterns.items():
                if pattern.search(line_stripped):
                    result['input_sources'].append(f"[{source_type}] {line_stripped[:80]}")
            
            # 检查危险操作
            for sink_type, pattern in sink_patterns.items():
                if pattern.search(line_stripped):
                    result['dangerous_sinks'].append(f"[{sink_type}] {line_stripped[:80]}")
            
            # 如果指定了目标变量，追踪其定义和使用
            if target_var:
                # 变量定义（赋值左侧）
                def_pattern = re.compile(rf'\b{re.escape(target_var)}\s*=')
                if def_pattern.search(line_stripped):
                    result['variable_defs'].append(line_stripped[:80])
                
                # 变量使用（非赋值左侧）
                use_pattern = re.compile(rf'\b{re.escape(target_var)}\b')
                if use_pattern.search(line_stripped) and not def_pattern.search(line_stripped):
                    result['variable_uses'].append(line_stripped[:80])
        
        return result
    
    async def _arun(
        self,
        function_name: str,
        variable_name: Optional[str] = None,
        version: str = "pre",
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None
    ) -> str:
        """异步执行"""
        return self._run(function_name, variable_name, version)


class SubmitAnalysisTool(BaseTool):
    """提交最终分析结果的工具"""
    
    name: str = "submit_analysis"
    description: str = """Submit your final vulnerability analysis.

Use this tool ONLY when you have gathered sufficient information to make a confident assessment.

Input should be a JSON with:
- vulnerability_found: 'Yes' or 'No'
- vulnerability_type: CWE ID (e.g., 'CWE-78')
- severity: 'High', 'Medium', 'Low', or 'None'
- is_fixed: 'Yes', 'No', or 'Partial'
- root_cause: Detailed explanation of the vulnerability's root cause
- fix_description: How the patch addresses the vulnerability
- reason: List of reasoning points supporting your conclusion"""
    args_schema: Type[BaseModel] = AnalysisResultInput
    return_direct: bool = True  # 直接返回结果，结束 Agent 循环
    
    def _run(
        self,
        vulnerability_found: Optional[str] = None,
        vulnerability_type: Optional[str] = None,
        severity: Optional[str] = None,
        is_fixed: Optional[str] = None,
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
                    vulnerability_found = payload.get("vulnerability_found")
                    vulnerability_type = payload.get("vulnerability_type")
                    severity = payload.get("severity")
                    is_fixed = payload.get("is_fixed")
                    root_cause = payload.get("root_cause")
                    fix_description = payload.get("fix_description")
                    reason = payload.get("reason")
                except json.JSONDecodeError:
                    pass
        elif isinstance(vulnerability_found, dict):
            payload = vulnerability_found
            vulnerability_found = payload.get("vulnerability_found")
            vulnerability_type = payload.get("vulnerability_type")
            severity = payload.get("severity")
            is_fixed = payload.get("is_fixed")
            root_cause = payload.get("root_cause")
            fix_description = payload.get("fix_description")
            reason = payload.get("reason")

        vulnerability_found = vulnerability_found or "Unknown"
        vulnerability_type = vulnerability_type or "Unknown"
        severity = severity or "Unknown"
        is_fixed = is_fixed or "Unknown"
        root_cause = root_cause or "Not analyzed"
        fix_description = fix_description or "Not analyzed"
        reason = reason or []

        context = get_tool_context()
        
        # 构建结果 JSON
        result = {
            "vulnerability_found": vulnerability_found,
            "scenario_match": "Yes" if vulnerability_found == "Yes" else "No",
            "property_match": "Yes" if is_fixed == "Yes" else "No",
            "Scenario_match & Property_match": "Yes" if (vulnerability_found == "Yes" and is_fixed == "Yes") else "No",
            "vulnerability_type": vulnerability_type,
            "severity": severity,
            "vulnerability_details": {
                "root_cause": root_cause,
                "attack_vector": "See reasoning for details",
                "impact": f"{severity} severity impact"
            },
            "fix_analysis": {
                "is_fixed": is_fixed,
                "fix_description": fix_description
            },
            "reason": reason,
            "reasoning_chain": context.get_reasoning_summary() if context else "N/A"
        }
        
        return json.dumps(result, indent=2, ensure_ascii=False)
    
    async def _arun(
        self,
        vulnerability_found: Optional[str] = None,
        vulnerability_type: Optional[str] = None,
        severity: Optional[str] = None,
        is_fixed: Optional[str] = None,
        root_cause: Optional[str] = None,
        fix_description: Optional[str] = None,
        reason: Optional[List[str]] = None,
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
        **kwargs
    ) -> str:
        """异步执行"""
        return self._run(
            vulnerability_found=vulnerability_found,
            vulnerability_type=vulnerability_type,
            severity=severity,
            is_fixed=is_fixed,
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
    'SubmitAnalysisTool'
]
