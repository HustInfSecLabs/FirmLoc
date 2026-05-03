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
from config import config_manager as global_config

class BinwalkAgent(Agent):
    """
    translated LangChain ReAct Agent translated
    translated、translated,translated
    """
    
    def __init__(self, chat_model: ChatModel) -> None:
        super().__init__(chat_model)
        self.agent = "Binwalk Agent"
        self.tool = "Binwalk"
        self.tool_status = "stop"
        self.tool_type = "terminal"
    
    @staticmethod
    def _sanitize_input(func: Callable) -> Callable:
        """translated: translated"""
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
        """translated"""
        return {'status': status, 'message': message}
    
    def _create_tools(self, task_id: str, firmware_path: str, work_dir: Path, firmware_dir: Path, local_firmware_path: Path) -> List[Tool]:
        """translated Agent translated"""
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
            translated binwalk translated
            Args:
                command: translated binwalk translated(translated 'binwalk' translated)
            Returns:
                translated
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
                
                output = f"translated: {result.returncode}\ntranslated:\n{result.stdout}\n"
                if result.stderr:
                    output += f"translated:\n{result.stderr}\n"
                return output
            except subprocess.TimeoutExpired:
                return "translated: translated(5translated)"
            except Exception as e:
                return f"translated: translated - {str(e)}"
        
        @self._sanitize_input
        def check_file_type(file_path: str) -> str:
            """
            translated
            Args:
                file_path: translated
            Returns:
                translated
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
                return f"translated: translated - {str(e)}"
        
        @self._sanitize_input
        def list_directory(directory: str = ".") -> str:
            """
            translated
            Args:
                directory: translated(translated)
            Returns:
                translated
            """
            def get_dir_size(path: Path) -> int:
                """translated"""
                try:
                    return sum(f.stat().st_size for f in path.rglob('*') if f.is_file())
                except:
                    return 0
            
            try:
                dir_arg = directory.strip().strip('"') if directory else ''
                full_path = firmware_dir / dir_arg if dir_arg and dir_arg != "." else firmware_dir
                if not full_path.exists():
                    return f"translated: translated - {full_path}"
                
                items = []
                for item in full_path.iterdir():
                    item_type = "translated" if item.is_dir() else "translated"
                    size = item.stat().st_size if item.is_file() else get_dir_size(item)
                    items.append(f"{item_type}: {item.name} ({size} translated)")
                
                return "\n".join(items) if items else "translated"
            except Exception as e:
                return f"translated: translated - {str(e)}"
        
        def check_extracted_files(dummy_input: str = "") -> str:
            """
            translated
            Args:
                dummy_input: translated,LangChain translated
            Returns:
                translated
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
                    return "translated"
                
                result = f"translated {len(extracted_dirs)} translated:\n"
                for idx, dir_path in enumerate(extracted_dirs, 1):
                    file_count = sum(1 for _ in Path(dir_path).rglob('*') if _.is_file())
                    abs_path = os.path.abspath(dir_path)
                    rel_path = os.path.relpath(dir_path, start=os.getcwd())
                    result += f"{idx}. translated: {abs_path}\n"
                    result += f"   translated: {rel_path} (translated {file_count} translated)\n"
                
                return result
            except Exception as e:
                return f"translated: translated - {str(e)}"
        
        @self._sanitize_input
        def analyze_binwalk_output(output: str) -> str:
            """
            translated binwalk translated,translated
            Args:
                output: binwalk translated
            Returns:
                translated
            """
            suggestions = []
            output_upper = output.upper()
            output_lower = output.lower()
            
            if "WARNING" in output_upper or "ERROR" in output_upper:
                suggestions.append("translated")
            
            if "DECIMAL" in output and "HEXADECIMAL" in output:
                suggestions.append("translated")
            else:
                suggestions.append("translated,translated")
            
            fs_types = {
                "squashfs": "Squashfs",
                "jffs2": "JFFS2",
                "cramfs": "CramFS",
                "ubifs": "UBIFS",
                "yaffs": "YAFFS"
            }
            for key, name in fs_types.items():
                if key in output_lower:
                    suggestions.append(f"translated {name} translated")
                    break
            
            return "translated:\n" + "\n".join(f"- {s}" for s in suggestions) if suggestions else "translated:\n- translated"
        
        return [
            Tool(
                name="execute_binwalk",
                func=execute_binwalk_command,
                description="translated binwalk translated.translated binwalk translated(translated 'binwalk' translated),translated '-Me /path/to/file' translated '--signature /path/to/file'"
            ),
            Tool(
                name="check_file_type",
                func=check_file_type,
                description="translated.translated"
            ),
            Tool(
                name="list_directory",
                func=list_directory,
                description="translated.translated,translated '.' translated"
            ),
            Tool(
                name="check_extracted_files",
                func=check_extracted_files,
                description="translated binwalk translated.translated,translated"
            ),
            Tool(
                name="analyze_output",
                func=analyze_binwalk_output,
                description="translated binwalk translated.translated binwalk translated"
            )
        ]
    
    def _create_react_prompt(self) -> ChatPromptTemplate:
        """translated ReAct Agent translated"""
        template = """translated,translated binwalk translated.

translated:
- translated: {firmware_path}
- translated: {work_dir}

translated.translated,translated:
1. translated
2. translated
3. translated

translated:
{tools}

translated: {tool_names}

translated:

Question: translated
Thought: translated
Action: translated,translated [{tool_names}] translated
Action Input: translated
Observation: translated
... (translated Thought/Action/Action Input/Observation translated N translated)
Thought: translated
Final Answer: translated

translated:
1. translated,translated(-e, -Me, --run-as=root)
2. translated,translated check_file_type translated
3. translated,translated
4. translated

translated!

Question: {input}
Thought: {agent_scratchpad}"""
        
        return ChatPromptTemplate.from_template(template)

    def _initialize_llm(self):
        """Initialize LangChain LLM."""
        from langchain_openai import ChatOpenAI

        model_name = getattr(self.chat_model, 'model_name', None)
        llm_key = global_config.resolve_llm_key()
        llm_section = f"LLM.{llm_key}"

        if not model_name:
            model_name = global_config.config.get(llm_section, {}).get("model_name", "")

        if hasattr(self.chat_model, 'client'):
            api_key = getattr(self.chat_model.client, 'api_key', None)
            base_url_obj = getattr(self.chat_model.client, 'base_url', None)
            base_url = str(base_url_obj) if base_url_obj else None
        else:
            llm_config = global_config.config.get(llm_section, {})
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
        translated ReAct Agent translated
        
        Returns:
            Dict[str, Any]: translated
        """
        if not task_id or not firmware_path:
            return self._create_error_response('error', 'translated: task_id translated firmware_path')
            
        if not os.path.exists(firmware_path):
            return self._create_error_response('error', f'translated: {firmware_path}')
        
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
            return self._create_error_response('error', f'translated: {copy_err}')
        
        config.update_tool_status("Online Search", "Binwalk")
        self.tool_status = "running"
        if on_status_update:
            on_status_update(None, self.tool, self.tool_status)
        
        try:
            tools = self._create_tools(task_id, firmware_path, work_dir, firmware_dir, local_firmware_path)
            llm = self._initialize_llm()
            
            agent = create_react_agent(llm, tools, self._create_react_prompt())
            agent_executor = AgentExecutor(
                agent=agent,
                tools=tools,
                verbose=True,
                max_iterations=20,
                handle_parsing_errors=True,
                return_intermediate_steps=True
            )
            
            question = f"translated binwalk translated {local_firmware_path}.translated,translated,translated."
            
            if send_message:
                await send_message(
                    "Agent translated...",
                    "command",
                    self.tool_type,
                    [{
                        "user": "Binwalk Agent",
                        "input": question,
                        "output": "translated..."
                    }],
                    agent=self.agent,
                    tool=self.tool,
                    tool_status="running"
                )
            
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: agent_executor.invoke({
                    "input": question,
                    "firmware_path": firmware_path,
                    "work_dir": str(work_dir)
                })
            )
            
            agent_log = []
            if 'intermediate_steps' in result:
                for step in result['intermediate_steps']:
                    action, observation = step
                    agent_log.append({
                        "thought": action.log if hasattr(action, 'log') else "translated",
                        "action": action.tool,
                        "action_input": action.tool_input,
                        "observation": observation
                    })
            
            log_file = firmware_dir / 'agent_log.json'
            with open(log_file, 'w', encoding='utf-8') as f:
                json.dump(agent_log, f, ensure_ascii=False, indent=2)
            
            search_roots = [firmware_dir, Path(firmware_path).parent]
            extracted_dirs = []
            for root in search_roots:
                pattern = root / f"_{firmware_name}*.extracted"
                extracted_dirs.extend(glob.glob(str(pattern)))
            extracted_dirs = sorted(set(extracted_dirs), key=os.path.getmtime)
            
            if not extracted_dirs:
                raise RuntimeError("Agent translated")
            
            actual_extracted_path = Path(extracted_dirs[-1])
            if not str(actual_extracted_path).startswith(str(firmware_dir)):
                dest_path = firmware_dir / actual_extracted_path.name
                if dest_path.exists():
                    shutil.rmtree(dest_path)
                shutil.move(str(actual_extracted_path), str(dest_path))
                actual_extracted_path = dest_path
            
            config.update_tool_status("Binwalk")
            self.tool_status = "completed"
            if on_status_update:
                on_status_update(tool_status=self.tool_status)
            
            if send_message:
                tool_content = [{
                    "user": "Binwalk Agent",
                    "input": question,
                    "output": result.get('output', 'translated'),
                    "agent_log": agent_log
                }]
                
                await send_message(
                    f"translated",
                    "command",
                    self.tool_type,
                    tool_content,
                    agent=self.agent,
                    tool=self.tool,
                    tool_status=self.tool_status
                )
                await asyncio.sleep(1)
            
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
            error_msg = f'Agent translated: {str(e)}'
            
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
                    [{"user": "Binwalk Agent", "input": "translated", "output": error_msg}],
                    agent=self.agent,
                    tool=self.tool,
                    tool_status=self.tool_status
                )
            
            return self._create_error_response('error', error_msg)
    
    def _update_status_ini(self, work_dir, firmware_name, result):
        """translated"""
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
                'message': f'translated {task_id} translated'
            }
        
        config = configparser.ConfigParser()
        config.read(status_file)
        
        if firmware_name is not None:
            if firmware_name in config.sections():
                return {key: value for key, value in config[firmware_name].items()}
            else:
                return {
                    'status': 'unknown',
                    'message': f'translated {firmware_name} translated'
                }
        else:
            results = {}
            for section in config.sections():
                results[section] = {key: value for key, value in config[section].items()}
            
            return results
