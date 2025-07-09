# agents/repair_agent.py

import os
import json
import subprocess
import re
from langchain.agents import create_react_agent, AgentExecutor, Tool
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from json_repair import repair_json
from langchain import hub
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.agents import AgentAction, AgentFinish
from langchain.callbacks.manager import CallbackManager
from langchain.prompts import PromptTemplate
from config import config_manager
import tiktoken
import ast
import traceback
import datetime

max_context_window = 128000
max_output_token_nums = 16384

enc = tiktoken.get_encoding("cl100k_base")
# enc = tiktoken.encoding_for_model("gpt-4o")

def clear_quote(input: str) -> str:
    return re.sub(r"^[`\"'\s]+|[`\"'\s]+$", "", input)

def build_tools(base_dir, send_message):
    @tool
    def terminal(cmd: str):
        """
        A toolkit for terminal operations across multiple operating systems.
        This toolkit provides a set of functions for terminal operations such as
        searching for files by name or content, executing shell commands, and
        managing terminal sessions.
            
        Args:
            cmd: The command to run.

        Returns:
            The result of executing the command
        """
        cmd = clear_quote(cmd)
        response = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            text=True,
            shell=True,
            errors="ignore",
            cwd=base_dir,
        )
        output = f"stdout: {response.stdout.strip()},\nstderr: {response.stderr.strip()}\n"
        send_message(content=output)
        return output
    
    @tool
    def file_read(filepath: str):
        """
        A toolkit for file read operation. This toolkit receives a
        param of filepath, and returns the content of the file.
            
        Args:
            filepath: the path of file to read.
        """
        filepath =  clear_quote(filepath)
        full_filepath = os.path.join(base_dir, filepath)

        try:
            with open(full_filepath, "r", encoding='utf-8') as fp:
                content = fp.read()
        except Exception as e:
            send_message(content=f"读取文件 {filepath} 失败: {e}")
            err_msg = f"无法读取文件 '{full_filepath}'：{e}"
            print(err_msg)
            return err_msg

        token_ids = enc.encode(content)
        token_nums = len(token_ids)

        if token_nums >=  max_output_token_nums:
            raise RuntimeError(f"待处理文件的 token 数: {token_nums} 超过当前模型输出的token数上限 {max_output_token_nums}，将导致文件写入失败，自动退出")
        send_message(content=content)
        # send_message(content=f"成功读取了文件{filepath}")
        return content
    
    @tool
    def file_write(input: str):
        """
        A toolkit for file write operation. This tookkit receive two param: the content and filepath, and then
        write the content into the file.

        Args:
            input: the str of the dict has the content and filepath to write. The input must be a strict JSON format string containing two keys. The two key must be `content` and `filepath`.Please avoid using triple quotes in the generated input; use single quotes whenever possible. If quotation marks are needed inside the `content` field of the JSON, make sure to use escape characters.
        """
        # 去掉外层多余引号
        text = clear_quote(input).strip()

        # 精确定位最外层花括号
        start = text.find('{')
        end   = text.rfind('}')
        if start < 0 or end < 0 or end <= start:
            result = "无法定位到 JSON/dict 边界，请检查输入格式。\n"
            send_message(content=result)
            return result

        snippet = text[start : end+1]

        # 尝试解析
        try:
            # 优先当 JSON 解析
            payload = json.loads(snippet)
        except json.JSONDecodeError:
            try:
                # 用 Python literal_eval 支持单引号 dict
                payload = ast.literal_eval(snippet)
            except Exception as e:
                result = f"解析失败，请检查输入，确保使用合法的 JSON 语法：{e}\n"
                send_message(content=result)
                return result

        # 校验必需字段
        for key in ("filepath", "content"):
            if key not in payload:
                result = f"缺少字段 `{key}`，可用字段：{list(payload.keys())}\n"
                send_message(content=result)
                return result

        relpath = payload["filepath"]
        content = payload["content"]
        abs_path = os.path.join(base_dir, relpath)

        # 确保目录存在
        parent_dir = os.path.dirname(abs_path)
        try:
            os.makedirs(parent_dir, exist_ok=True)
        except Exception as e:
            result = f"创建目录失败 '{parent_dir}'：{e}\n"
            send_message(content=result)
            return result

        try:
            with open(abs_path, "w", encoding="utf-8") as fw:
                fw.write(content)
        except (IOError, OSError) as e:
            result = f"无法写入文件 '{abs_path}'：{e}\n"
            send_message(content=result)
            return result

        result = True
        send_message(content="写入文件成功")
        return result
    
    terminal_tool = Tool(name='Terminal',
        func=terminal,
        description="""\
        A toolkit for terminal operations across multiple operating systems.
        This toolkit provides a set of functions for terminal operations such as
        searching for files by name or content, executing shell commands, and
        managing terminal sessions.

        Args:
            cmd: The command to run.

        Returns:
            The result of executing the command\
        """
    )

    file_write_tool = Tool(name='File Write',
        func=file_write,
        description="""\
        A toolkit for file write operation. This tookkit receive two param: the content and filepath, and then
        write the content into the file.

        Args:
        input: the str of the dict has the content and filepath to write. The two key must be `content` and `filepath`\
        """
    )

    file_read_tool = Tool(name='File Read',
        func=file_read,
        description="""\
        A toolkit for file read operation. This toolkit receive a
        param of filepath, and return the content of file.

        Args:
        filepath: the path of file to read.\
        """
    )

    tools = [terminal_tool, file_read_tool, file_write_tool]

    return tools

def save_llm_result(dir_path, result=None, error=None, tb_str=None, extra_log=""):
    os.makedirs(dir_path, exist_ok=True)
    json_path = os.path.join(dir_path, "llm_result.json")
    record = {}
    record["timestamp"] = datetime.datetime.now().isoformat()

    # 纯文本日志
    record["log_text"] = extra_log

    # 字典日志
    if isinstance(result, dict):
        inp = result.get("input")
        if inp is not None:
            record["input"] = inp

        out = result.get("output")
        if out is not None:
            record["output"] = out

        steps = result.get("intermediate_steps")
        # intermediate_steps 如果存在且是 list，则写入；否则跳过
        if isinstance(steps, list) and len(steps) > 0:
            record["intermediate_steps"] = []
            for action, observation in steps:
                step = {}
                # action 保留 tool 名称和输入
                tool_name = getattr(action, "tool", None)
                tool_input = getattr(action, "tool_input", None)
                if tool_name is not None:
                    step["action"] = {"tool": tool_name}
                    if tool_input is not None:
                        step["action"]["tool_input"] = tool_input
                # observation
                step["observation"] = observation
                record["intermediate_steps"].append(step)

    # error
    if error is not None:
        record["error"] = str(error)

    # traceback
    if tb_str is not None:
        record["traceback"] = tb_str

    if not os.path.exists(json_path):
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump([], f, ensure_ascii=False, indent=2)

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            existing = json.load(f)
            if not isinstance(existing, list):
                existing = []
    except (json.JSONDecodeError, IOError):
        existing = []

    existing.append(record)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(existing, f, ensure_ascii=False, indent=2)

    return True

def run_repair_agent(base_dir: str, websocket_sender):    
    try:
        llm = ChatOpenAI(
            model=config_manager.config["LLM.GPT"]["model_name"],
            temperature=0,
            max_tokens=None,
            timeout=None,
            max_retries=3,
            api_key = config_manager.config["LLM.GPT"]["api_key"]
        )
        tools = build_tools(base_dir, websocket_sender)
        prompt = hub.pull("hwchase17/react")
        prompt.template += "\n[系统指令] 所有输出必须直接使用中文，禁止声明语言切换行为。"
        agent = create_react_agent(llm, tools, prompt)
        
        log_info = f"Start process the .c file in {base_dir}"
        save_llm_result(base_dir, result=None, error=None, tb_str=None, extra_log=log_info)

        QUESTION = """\
    Your task is to ensure that the .c file in the folder can be compiled successfully. This file is pseudocode automatically generated by IDA Pro.

    ### Compilation Check:
    - You MUST use the command `gcc -c -w -fmax-errors=0` to check whether .c file can be compiled.
    - A successful result means that a `.o` file (e.g., `example--repair.o`) is generated after compiling the modified file.
    - Do NOT add any redundant suffixes or prefixes to the output `.o` file name.

    ### File Modification Instructions:
    - If there are compilation errors, modify the .c file minimally to fix the errors and save the modified file with the suffix `--repair`, such as `example--repair.c`.

    ### Constraints:
    - **Do not change the logic of the original code.**
    - You CANNOT add or remove function parameters.
    - You CANNOT remove or comment out any function or logic.
    - You MAY adjust parameter data types or add `extern`/global declarations if necessary.
    - Do not affect the semantics of the original code, including its original control flow, data flow, or logic.

    ### Commenting Requirement:
    - Use comments to clearly mark every modification. The format is: `# Modified: [reason]`.
    """
        
        CHINESE_QUESTION = f"""
    你的任务是确保文件夹中的 `.c` 文件能够成功编译，
    该文件是由 IDA Pro 自动生成的伪代码。

    编译检查：
    - 你必须使用以下命令检查是否可以编译：`gcc -c -w -fmax-errors=0`
    - 编译成功的标志是生成一个 `.o` 文件（例如 `example--repair.o`）。
    - 不要在输出的 `.o` 文件名中添加任何冗余的前缀或后缀。

    文件修改说明：
    - 如果存在编译错误，请尽量小幅修改 `.c` 文件以修复错误，
    并将修改后的文件以 `--repair` 作为后缀保存，例如 `example--repair.c`。

    约束条件：
    - 不得更改原始代码的逻辑。
        - 不得添加或删除函数参数。
        - 不得删除或注释掉任何函数或逻辑。
        - 如有必要，可以调整参数的数据类型或添加 `extern`/全局声明。
    - 不得影响原始代码的语义，包括其原始的控制流、数据流或逻辑。

    注释要求：
    - 使用注释清楚标记每一处修改，格式如下：`// Modified: [原因]`。

    """

        callback = CallbackHandler(send_message=websocket_sender)

        # 运行代理
        agent_executor = AgentExecutor(
            agent=agent, 
            tools=tools, 
            verbose=False, 
            callbacks=[callback], 
            handle_parsing_errors=True, 
            return_intermediate_steps=True
        )
        
        result = agent_executor.invoke({"input": CHINESE_QUESTION})
        save_llm_result(base_dir, result)

    except Exception as e:
        tb_str = traceback.format_exc()
        save_llm_result(base_dir, result=None, error=e, tb_str=tb_str)
        return False, f"{str(e)}"

    return True, "修复完成"


class CallbackHandler(BaseCallbackHandler):
    def __init__(self, send_message):
        self.send_message = send_message

    def on_agent_action(self, action: AgentAction, **kwargs):
        thought = action.log.strip()
        content = thought
        self.send_message(content=content)

    def on_agent_finish(self, finish: AgentFinish, **kwargs):
        content = finish.log.strip()
        self.send_message(content=content)
