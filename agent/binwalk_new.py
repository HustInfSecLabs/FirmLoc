import os
import shlex
import shutil
import subprocess
import json
import configparser
from pathlib import Path
from functools import wraps
from .base import Agent
from model import ChatModel
import glob
import asyncio
from utils import ConfigManager
from typing import Dict, Any, List, Callable
from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import Tool
from langchain_core.prompts import ChatPromptTemplate

class BinwalkAgent(Agent):
    """
    使用 LangChain ReAct Agent 对固件文件进行分析和提取
    具有思考、执行和反思能力，能够在失败后分析原因并尝试解决
    """
    
    def __init__(self, chat_model: ChatModel) -> None:
        super().__init__(chat_model)
        self.agent = "Binwalk Agent"
        self.tool = "Binwalk"
        self.tool_status = "stop"
        self.tool_type = "terminal"
    
    @staticmethod
    def _sanitize_input(func: Callable) -> Callable:
        """装饰器: 自动清理工具函数的输入参数"""
        @wraps(func)
        def wrapper(input_str: str = "") -> str:
            cleaned_input = (input_str or "").strip()
            if not cleaned_input:
                return func("")
            first_line = cleaned_input.splitlines()[0].strip()
            for stop_token in ("Observ", "Observation:", "Observation"):
                if stop_token in first_line:
                    first_line = first_line.split(stop_token)[0].strip()
            return func(first_line)
        return wrapper
        
    def _create_error_response(self, status: str, message: str) -> Dict[str, str]:
        """统一的错误响应格式"""
        return {'status': status, 'message': message}
    
    def _create_tools(self, task_id: str, firmware_path: str, work_dir: Path, firmware_dir: Path, local_firmware_path: Path) -> List[Tool]:
        """创建 Agent 可用的工具集"""
        local_firmware_name = local_firmware_path.name

        def _resolve_file_path(path_str: str) -> Path:
            cleaned = (path_str or "").strip().strip('"')
            if not cleaned:
                return local_firmware_path
            candidate = Path(cleaned).expanduser()
            if not candidate.is_absolute():
                candidate = (firmware_dir / candidate).resolve()
            candidate = candidate.resolve()
            return candidate
        
        @self._sanitize_input
        def execute_binwalk_command(command: str) -> str:
            """
            执行 binwalk 命令
            Args:
                command: 要执行的 binwalk 命令参数（不包含 'binwalk' 本身）
            Returns:
                命令执行结果
            """
            try:
                args = shlex.split(command) if command else []

                def _has_existing_file(arguments: List[str]) -> bool:
                    for arg in arguments:
                        stripped = arg.strip('"')
                        if not stripped or stripped.startswith('-'):
                            continue
                        candidate = Path(stripped).expanduser()
                        if candidate.exists():
                            return True
                        rel_candidate = (firmware_dir / stripped).resolve()
                        if rel_candidate.exists():
                            return True
                    return False

                if not _has_existing_file(args):
                    args.append(local_firmware_name)

                full_command = ['binwalk'] + args
                result = subprocess.run(
                    full_command,
                    capture_output=True,
                    text=True,
                    cwd=str(firmware_dir),
                    timeout=300
                )
                
                output = f"返回码: {result.returncode}\n标准输出:\n{result.stdout}\n"
                if result.stderr:
                    output += f"标准错误:\n{result.stderr}\n"
                return output
            except subprocess.TimeoutExpired:
                return "错误: 命令执行超时（5分钟）"
            except Exception as e:
                return f"错误: 命令执行异常 - {str(e)}"
        
        @self._sanitize_input
        def check_file_type(file_path: str) -> str:
            """
            检查文件类型
            Args:
                file_path: 文件路径
            Returns:
                文件类型信息
            """
            try:
                target = _resolve_file_path(file_path)
                result = subprocess.run(
                    ['file', str(target)],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                return result.stdout.strip()
            except Exception as e:
                return f"错误: 无法检查文件类型 - {str(e)}"
        
        @self._sanitize_input
        def list_directory(directory: str = ".") -> str:
            """
            列出目录内容
            Args:
                directory: 目录路径（相对于工作目录）
            Returns:
                目录内容列表
            """
            def get_dir_size(path: Path) -> int:
                """递归计算目录大小"""
                try:
                    return sum(f.stat().st_size for f in path.rglob('*') if f.is_file())
                except:
                    return 0
            
            try:
                dir_arg = directory.strip().strip('"') if directory else ''
                full_path = firmware_dir / dir_arg if dir_arg and dir_arg != "." else firmware_dir
                if not full_path.exists():
                    return f"错误: 目录不存在 - {full_path}"
                
                items = []
                for item in full_path.iterdir():
                    item_type = "目录" if item.is_dir() else "文件"
                    size = item.stat().st_size if item.is_file() else get_dir_size(item)
                    items.append(f"{item_type}: {item.name} ({size} 字节)")
                
                return "\n".join(items) if items else "目录为空"
            except Exception as e:
                return f"错误: 无法列出目录 - {str(e)}"
        
        def check_extracted_files(dummy_input: str = "") -> str:
            """
            检查是否成功提取了文件
            Args:
                dummy_input: 占位参数，LangChain 会传递但不使用
            Returns:
                提取结果信息
            """
            try:
                firmware_name = os.path.basename(firmware_path)
                search_roots = [firmware_dir, Path(firmware_path).parent]
                extracted_dirs = []
                for root in search_roots:
                    pattern = root / f"_{firmware_name}*.extracted"
                    extracted_dirs.extend(glob.glob(str(pattern)))
                extracted_dirs = sorted(set(extracted_dirs), key=os.path.getmtime)
                
                if not extracted_dirs:
                    return "未找到提取的目录"
                
                result = f"找到 {len(extracted_dirs)} 个提取目录:\n"
                for idx, dir_path in enumerate(extracted_dirs, 1):
                    file_count = sum(1 for _ in Path(dir_path).rglob('*') if _.is_file())
                    # 转换为绝对路径
                    abs_path = os.path.abspath(dir_path)
                    # 计算相对于程序运行目录的路径
                    rel_path = os.path.relpath(dir_path, start=os.getcwd())
                    result += f"{idx}. 绝对路径: {abs_path}\n"
                    result += f"   相对路径: {rel_path} (包含 {file_count} 个文件)\n"
                
                return result
            except Exception as e:
                return f"错误: 无法检查提取文件 - {str(e)}"
        
        @self._sanitize_input
        def analyze_binwalk_output(output: str) -> str:
            """
            分析 binwalk 输出，提供建议
            Args:
                output: binwalk 的输出内容
            Returns:
                分析结果和建议
            """
            suggestions = []
            output_upper = output.upper()
            output_lower = output.lower()
            
            # 检查错误和警告
            if "WARNING" in output_upper or "ERROR" in output_upper:
                suggestions.append("检测到警告或错误信息")
            
            # 检查文件结构识别
            if "DECIMAL" in output and "HEXADECIMAL" in output:
                suggestions.append("成功识别文件结构")
            else:
                suggestions.append("可能未识别到文件结构，建议尝试其他参数")
            
            # 检测文件系统类型
            fs_types = {
                "squashfs": "Squashfs",
                "jffs2": "JFFS2",
                "cramfs": "CramFS",
                "ubifs": "UBIFS",
                "yaffs": "YAFFS"
            }
            for key, name in fs_types.items():
                if key in output_lower:
                    suggestions.append(f"检测到 {name} 文件系统")
                    break
            
            return "分析结果:\n" + "\n".join(f"- {s}" for s in suggestions) if suggestions else "分析结果:\n- 输出看起来正常"
        
        return [
            Tool(
                name="execute_binwalk",
                func=execute_binwalk_command,
                description="执行 binwalk 命令。输入应该是 binwalk 的参数（不包含 'binwalk' 本身），例如 '-Me /path/to/file' 或 '--signature /path/to/file'"
            ),
            Tool(
                name="check_file_type",
                func=check_file_type,
                description="检查文件类型。输入应该是文件的完整路径"
            ),
            Tool(
                name="list_directory",
                func=list_directory,
                description="列出目录内容。输入应该是相对于工作目录的路径，或使用 '.' 表示工作目录"
            ),
            Tool(
                name="check_extracted_files",
                func=check_extracted_files,
                description="检查 binwalk 是否成功提取了文件。输入可以是任意值或留空，工具不使用输入参数"
            ),
            Tool(
                name="analyze_output",
                func=analyze_binwalk_output,
                description="分析 binwalk 输出并提供建议。输入应该是 binwalk 命令的输出内容"
            )
        ]
    
    def _create_react_prompt(self) -> ChatPromptTemplate:
        """创建 ReAct Agent 的提示模板"""
        template = """你是一个固件解包专家，负责使用 binwalk 工具提取固件文件。

当前任务:
- 固件文件路径: {firmware_path}
- 工作目录: {work_dir}

你的目标是成功提取固件文件。如果遇到失败，你需要:
1. 分析失败原因
2. 思考可能的解决方案
3. 尝试不同的方法

可用工具:
{tools}

工具名称: {tool_names}

使用以下格式:

Question: 需要完成的任务
Thought: 你应该思考该做什么
Action: 要采取的行动，应该是 [{tool_names}] 之一
Action Input: 行动的输入
Observation: 行动的结果
... (这个 Thought/Action/Action Input/Observation 可以重复 N 次)
Thought: 我现在知道最终答案了
Final Answer: 对原始输入问题的最终答案

常见问题和解决方案:
1. 如果提取失败，尝试使用不同的参数（-e, -Me, --run-as=root）
2. 如果未识别文件系统，先使用 check_file_type 检查文件类型
3. 如果提取目录为空，检查是否需要特殊权限或工具
4. 每次执行后都要检查提取结果

开始!

Question: {input}
Thought: {agent_scratchpad}"""
        
        return ChatPromptTemplate.from_template(template)

    def _initialize_llm(self):
        """初始化 LangChain LLM"""
        from langchain_openai import ChatOpenAI
        from config import config_manager as global_config
        
        model_name = getattr(self.chat_model, 'model_name', None)
        if not model_name:
            model_name = global_config.config.get("LLM.DeepSeek", {}).get("model_name", "default")
        
        # 获取 API 配置
        if hasattr(self.chat_model, 'client'):
            api_key = getattr(self.chat_model.client, 'api_key', None)
            base_url_obj = getattr(self.chat_model.client, 'base_url', None)
            base_url = str(base_url_obj) if base_url_obj else None
        else:
            llm_config = global_config.config.get("LLM.DeepSeek", {})
            api_key = llm_config.get("api_key", "")
            base_url = llm_config.get("base_url", "")
        
        return ChatOpenAI(
            model=model_name,
            api_key=api_key,
            base_url=base_url,
            temperature=0.7
        )
    
    async def process(self, task_id: str, firmware_path: str, config: ConfigManager, send_message=None, on_status_update=None) -> Dict[str, Any]:
        """
        使用 ReAct Agent 处理固件提取任务
        
        Returns:
            Dict[str, Any]: 始终返回字典格式的结果
        """
        # 参数验证
        if not task_id or not firmware_path:
            return self._create_error_response('error', '缺少必要参数: task_id 或 firmware_path')
            
        if not os.path.exists(firmware_path):
            return self._create_error_response('error', f'固件文件不存在: {firmware_path}')
        
        firmware_name = os.path.basename(firmware_path)
        work_dir = Path(f'./history/{task_id}/binwalk')
        os.makedirs(work_dir, exist_ok=True)
        
        firmware_dir = work_dir / firmware_name
        os.makedirs(firmware_dir, exist_ok=True)
        local_firmware_path = firmware_dir / firmware_name
        try:
            if not local_firmware_path.exists() or os.path.getsize(local_firmware_path) != os.path.getsize(firmware_path):
                shutil.copy2(firmware_path, local_firmware_path)
        except Exception as copy_err:
            return self._create_error_response('error', f'复制固件文件失败: {copy_err}')
        
        # 更新状态
        config.update_tool_status("Online Search", "Binwalk")
        self.tool_status = "running"
        if on_status_update:
            on_status_update(None, self.tool, self.tool_status)
        
        try:
            # 创建工具集和 LLM
            tools = self._create_tools(task_id, firmware_path, work_dir, firmware_dir, local_firmware_path)
            llm = self._initialize_llm()
            
            # 创建 ReAct Agent
            agent = create_react_agent(llm, tools, self._create_react_prompt())
            agent_executor = AgentExecutor(
                agent=agent,
                tools=tools,
                verbose=True,
                max_iterations=20,
                handle_parsing_errors=True,
                return_intermediate_steps=True
            )
            
            # 准备输入
            question = f"请使用 binwalk 提取固件文件 {local_firmware_path}。首先检查文件类型，然后选择合适的参数进行提取，最后验证提取是否成功。"
            
            # 发送思考消息
            if send_message:
                await send_message(
                    "Agent 开始分析固件文件并规划提取策略...",
                    "command",
                    self.tool_type,
                    [{
                        "user": "Binwalk Agent",
                        "input": question,
                        "output": "正在思考..."
                    }],
                    agent=self.agent,
                    tool=self.tool,
                    tool_status="running"
                )
            
            # 执行 Agent（在异步上下文中运行同步函数）
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: agent_executor.invoke({
                    "input": question,
                    "firmware_path": firmware_path,
                    "work_dir": str(work_dir)
                })
            )
            
            # 记录 Agent 的思考过程
            agent_log = []
            if 'intermediate_steps' in result:
                for step in result['intermediate_steps']:
                    action, observation = step
                    agent_log.append({
                        "thought": action.log if hasattr(action, 'log') else "执行工具",
                        "action": action.tool,
                        "action_input": action.tool_input,
                        "observation": observation
                    })
            
            # 保存 Agent 日志
            log_file = firmware_dir / 'agent_log.json'
            with open(log_file, 'w', encoding='utf-8') as f:
                json.dump(agent_log, f, ensure_ascii=False, indent=2)
            
            # 检查提取结果
            search_roots = [firmware_dir, Path(firmware_path).parent]
            extracted_dirs = []
            for root in search_roots:
                pattern = root / f"_{firmware_name}*.extracted"
                extracted_dirs.extend(glob.glob(str(pattern)))
            extracted_dirs = sorted(set(extracted_dirs), key=os.path.getmtime)
            
            if not extracted_dirs:
                raise RuntimeError("Agent 执行完成但未找到提取的目录")
            
            actual_extracted_path = Path(extracted_dirs[-1])
            if not str(actual_extracted_path).startswith(str(firmware_dir)):
                dest_path = firmware_dir / actual_extracted_path.name
                if dest_path.exists():
                    shutil.rmtree(dest_path)
                shutil.move(str(actual_extracted_path), str(dest_path))
                actual_extracted_path = dest_path
            
            # 更新状态
            config.update_tool_status("Binwalk")
            self.tool_status = "completed"
            if on_status_update:
                on_status_update(tool_status=self.tool_status)
            
            # 发送完成消息
            if send_message:
                tool_content = [{
                    "user": "Binwalk Agent",
                    "input": question,
                    "output": result.get('output', '提取完成'),
                    "agent_log": agent_log
                }]
                
                await send_message(
                    f"固件提取完成",
                    "command",
                    self.tool_type,
                    tool_content,
                    agent=self.agent,
                    tool=self.tool,
                    tool_status=self.tool_status
                )
                await asyncio.sleep(1)
            
            # 保存结果
            result_data = {
                'status': 'success',
                'binwalk_result_path': str(log_file),
                'extracted_files_path': str(actual_extracted_path),
                'agent_output': result.get('output', ''),
                'iterations': len(agent_log)
            }
            
            self._update_status_ini(work_dir, firmware_name, result_data)
            
            return result_data
            
        except Exception as e:
            error_msg = f'Agent 执行过程中发生错误: {str(e)}'
            
            # 更新状态
            config.update_tool_status("Binwalk")
            self.tool_status = "error"
            if on_status_update:
                on_status_update(tool_status=self.tool_status)
            
            error_result = {'status': 'error', 'message': error_msg}
            self._update_status_ini(work_dir, firmware_name, error_result)
            
            if send_message:
                await send_message(
                    error_msg,
                    "command",
                    self.tool_type,
                    [{"user": "Binwalk Agent", "input": "固件提取", "output": error_msg}],
                    agent=self.agent,
                    tool=self.tool,
                    tool_status=self.tool_status
                )
            
            return self._create_error_response('error', error_msg)
    
    def _update_status_ini(self, work_dir, firmware_name, result):
        """更新状态"""
        status_file = work_dir / 'status.ini'
        
        config = configparser.ConfigParser()
        if os.path.exists(status_file):
            config.read(status_file)
        
        if config.has_section(firmware_name):
            config.remove_section(firmware_name)
        
        config.add_section(firmware_name)
        
        for key, value in result.items():
            config.set(firmware_name, key, str(value))
        
        with open(status_file, 'w') as f:
            config.write(f)
    
    def get_result(self, task_id: str, firmware_name=None) -> dict:
        work_dir = Path(f'./history/{task_id}/binwalk')
        status_file = work_dir / 'status.ini'
        
        if not os.path.exists(status_file):
            return {
                'status': 'unknown',
                'message': f'未找到任务 {task_id} 的处理结果'
            }
        
        config = configparser.ConfigParser()
        config.read(status_file)
        
        if firmware_name is not None:
            # 返回特定固件的结果
            if firmware_name in config.sections():
                return {key: value for key, value in config[firmware_name].items()}
            else:
                return {
                    'status': 'unknown',
                    'message': f'未找到固件 {firmware_name} 的处理结果'
                }
        else:
            # 返回所有固件的结果
            results = {}
            for section in config.sections():
                results[section] = {key: value for key, value in config[section].items()}
            
            return results
