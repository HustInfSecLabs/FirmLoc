# repair_agent_v2_with_websocket.py

import os
import json
import subprocess
import re
import tiktoken
import ast
import traceback
import argparse
import datetime
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

# LLM client from websocket version
# from langchain_openai import ChatOpenAI
from openai import OpenAI
from config import config_manager

# encoding
try:
    enc = tiktoken.get_encoding("cl100k_base")
except Exception:
    # fallback
    enc = tiktoken.encoding_for_model("gpt-4o")

# ---- constants  ----
MAX_CONTEXT_WINDOW = 128000
TOOL_MAX_OUTPUT_TOKENS = 32768
LLM_MAX_OUTPUT_TOKENS = 8192

PRINT_MAX_MESSAGE_TOKENS = 600
PRINT_MAX_OBSERVATION_TOKENS = 600
MAX_READ_CODE_SLICE_LINES = 500
MAX_PER_HISTORY_MESSAGE_TOKENS = 4096

DEFAULT_RECENT_STEPS_COUNT = 9
DEFAULT_RECENT_STEPS_OVERFLOW_COUNT = 4
DEFAULT_SUMMARY_MAX_LINES = 200
DEFAULT_SUMMARY_RENDER_LINES = 40
DEFAULT_SUMMARY_KEEP_ON_OVERFLOW = 20

# ---- small helpers ----

def clear_quote(input: str) -> str:
    return re.sub(r"^[`\"'\s]+|[`\"'\s]+$", "", (input or ""))

def truncate_text_by_tokens(text: str, max_tokens: int) -> str:
    token_ids = enc.encode(text or "")
    if len(token_ids) <= max_tokens:
        return text or ""
    return enc.decode(token_ids[:max_tokens])

def token_len(text: str) -> int:
    return len(enc.encode(text or ""))

def _fmt_token_usage(used: int, limit: int) -> str:
    if limit <= 0:
        return f"{used}/?"
    pct = (used / limit) * 100
    used_k = used / 1000.0
    limit_k = limit / 1000.0
    return f"{used}/{limit} ({used_k:.1f}k/{limit_k:.0f}k, {pct:.2f}%)"

def _safe_preview(text: str, max_tokens: int) -> str:
    text = (text or "").strip()
    if not text:
        return ""
    preview = truncate_text_by_tokens(text, max_tokens)
    if token_len(preview) < token_len(text):
        return preview.rstrip() + "\n...[已截断]"
    return preview

def parse_gcc_error_lines(lines: List[str]) -> List[dict]:
    errors: List[dict] = []
    current_error: Optional[dict] = None
    caret_line_re = re.compile(r"^\s*\|?\s*\^")

    i = 0
    while i < len(lines):
        line = lines[i].rstrip("\n")

        error_match = re.match(
            r"^(.+?):(\d+):(\d+):\s*(error|warning|note):\s*(.+)$", line
        )

        if error_match:
            if current_error:
                errors.append(current_error)

            file_path = error_match.group(1)
            line_num = int(error_match.group(2))
            col_num = int(error_match.group(3))
            error_type = error_match.group(4)
            message = error_match.group(5)

            code_line = ""
            if i + 1 < len(lines):
                next_line = lines[i + 1].rstrip("\n")
                if not caret_line_re.match(next_line) and not re.match(
                    r"^.+?:\d+:\d+:", next_line
                ):
                    code_line = next_line
                    i += 1
                else:
                    j = i + 1
                    while j < len(lines) and j < i + 5:
                        temp_line = lines[j].rstrip("\n")
                        if caret_line_re.match(temp_line):
                            j += 1
                            continue
                        if re.match(r"^.+?:\d+:\d+:", temp_line):
                            break
                        code_line = temp_line
                        i = j
                        break
                        j += 1

            current_error = {
                "file": file_path,
                "line": line_num,
                "col": col_num,
                "type": error_type,
                "message": message,
                "code": code_line,
            }
        elif current_error and caret_line_re.match(line):
            i += 1
            continue
        elif current_error and line:
            current_error["message"] += " " + line.strip()

        i += 1

    if current_error:
        errors.append(current_error)

    return errors

def format_gcc_error(error: dict) -> str:
    prefix = f"{error['file']}:{error['line']}:{error['col']}: {error['type']}: {error['message']}"
    code = error.get("code")
    if code:
        return f"{prefix}\n    {code}"
    return prefix

@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    func: Callable[[str], str]


# ---- save_llm_result ----
def save_llm_result(dir_path, result=None, error=None, tb_str=None, extra_log=""):
    os.makedirs(dir_path, exist_ok=True)
    json_path = os.path.join(dir_path, "llm_result.json")
    record = {}
    record["timestamp"] = datetime.datetime.now().isoformat()
    record["log_text"] = extra_log

    if isinstance(result, dict):
        inp = result.get("input")
        if inp is not None:
            record["input"] = inp

        out = result.get("output")
        if out is not None:
            record["output"] = out

        steps = result.get("intermediate_steps")
        if isinstance(steps, list) and len(steps) > 0:
            record["intermediate_steps"] = []
            for action, observation in steps:
                step = {}
                tool_name = getattr(action, "tool", None)
                tool_input = getattr(action, "tool_input", None)
                if tool_name is not None:
                    step["action"] = {"tool": tool_name}
                    if tool_input is not None:
                        step["action"]["tool_input"] = tool_input
                step["observation"] = observation
                record["intermediate_steps"].append(step)

    if error is not None:
        record["error"] = str(error)
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

# ---- tools builder  ----
def build_tools(base_dir: str, send_message: Callable[..., None]) -> Dict[str, ToolSpec]:
    def terminal(cmd: str) -> str:
        cmd = clear_quote(cmd)
        try:
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
        except Exception as e:
            out = f"终端执行失败: {e}\n{traceback.format_exc()}"
            send_message(content=out)
            return out

        output = (
            f"标准输出(stdout):\n{response.stdout.strip()}\n\n"
            f"标准错误(stderr):\n{response.stderr.strip()}\n"
        )
        token_ids = enc.encode(output)
        if len(token_ids) <= TOOL_MAX_OUTPUT_TOKENS:
            send_message(content=output)
            return output

        truncated = enc.decode(token_ids[:TOOL_MAX_OUTPUT_TOKENS])
        truncated_msg = (
            truncated
            + "\n\n[输出已因令牌上限被截断。可使用 grep/head/tail 重新运行命令以获取具体信息。]"
        )
        send_message(content=truncated_msg)
        return truncated_msg

    def read_code_slice(input: str) -> str:
        text = clear_quote(input).strip()
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            try:
                payload = ast.literal_eval(text)
            except Exception as e:
                out = f"输入无效，需要 JSON/dict，包含 filepath/line/context: {e}"
                send_message(content=out)
                return out

        for key in ("filepath", "line"):
            if key not in payload:
                out = f"缺少必需字段 `{key}`"
                send_message(content=out)
                return out

        relpath = str(payload["filepath"]).strip()
        try:
            target_line = int(payload["line"])
        except (TypeError, ValueError):
            out = "`line` 必须是整数(从 1 开始)"
            send_message(content=out)
            return out

        try:
            ctx = int(payload.get("context", 5))
        except (TypeError, ValueError):
            out = "`context` 必须是整数"
            send_message(content=out)
            return out

        abs_path = os.path.join(base_dir, relpath)
        if not os.path.exists(abs_path):
            out = f"未找到文件: {abs_path}"
            send_message(content=out)
            return out

        try:
            with open(abs_path, "r", encoding="utf-8", errors="ignore") as fp:
                lines = fp.readlines()
        except Exception as e:
            out = f"无法读取文件 '{abs_path}': {e}"
            send_message(content=out)
            return out

        if target_line < 1 or target_line > len(lines):
            out = f"第 {target_line} 行超出范围（文件共有 {len(lines)} 行）"
            send_message(content=out)
            return out

        start = max(1, target_line - ctx)
        end = min(len(lines), target_line + ctx)
        slice_len = end - start + 1
        if slice_len > MAX_READ_CODE_SLICE_LINES:
            out = (
                f"[切片过大: {relpath}:{start}-{end} ({slice_len} 行)]\n"
                f"请缩小 context 或重新读取指定区域。"
            )
            send_message(content=out)
            return out

        snippet_lines = []
        for idx in range(start, end + 1):
            snippet_lines.append(f"{idx}: {lines[idx - 1].rstrip()}")

        snippet = "\n".join(snippet_lines)
        header = f"[代码切片 {relpath}:{start}-{end} (context={ctx})]"
        result = f"{header}\n{snippet}"
        send_message(content=result)
        return result

    def patch_apply(input: str) -> str:
        text = clear_quote(input).strip()
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            try:
                payload = ast.literal_eval(text)
            except Exception as e:
                out = f"输入无效，需要 JSON/dict: {e}"
                send_message(content=out)
                return out

        for key in ("filepath", "action", "start"):
            if key not in payload:
                out = f"缺少必需字段 `{key}`"
                send_message(content=out)
                return out

        action = str(payload.get("action", "")).lower()
        if action not in ("add", "delete", "update"):
            out = "action 必须是: add, delete, update 之一"
            send_message(content=out)
            return out

        relpath = str(payload["filepath"]).strip()
        try:
            start = int(payload["start"])
        except (TypeError, ValueError):
            out = "start 必须是整数(从 1 开始)"
            send_message(content=out)
            return out

        try:
            end = int(payload.get("end", start))
        except (TypeError, ValueError):
            out = "end 必须是整数(从 1 开始)"
            send_message(content=out)
            return out

        content = payload.get("content", "")
        needs_content = action in ("add", "update")
        if needs_content and (content is None or content == ""):
            out = "add/update 操作必须提供 content"
            send_message(content=out)
            return out

        abs_path = os.path.join(base_dir, relpath)
        file_exists = os.path.exists(abs_path)
        lines: List[str] = []
        if file_exists:
            try:
                with open(abs_path, "r", encoding="utf-8", errors="ignore") as fp:
                    lines = fp.readlines()
            except Exception as e:
                out = f"unable to read file '{abs_path}': {e}"
                send_message(content=out)
                return out
        else:
            if action != "add":
                out = f"用于执行 {action} 的文件不存在: {abs_path}"
                send_message(content=out)
                return out

        total_lines = len(lines)
        if start < 1:
            out = "start 必须 >= 1"
            send_message(content=out)
            return out
        if action in ("delete", "update"):
            if end < start:
                out = "end 必须 >= start"
                send_message(content=out)
                return out
            if total_lines == 0:
                out = f"文件为空，无法执行 {action}"
                send_message(content=out)
                return out
            if start > total_lines:
                out = f"start {start} 超出范围（文件共有 {total_lines} 行）"
                send_message(content=out)
                return out
            if end > total_lines:
                out = f"end {end} 超出范围（文件共有 {total_lines} 行）"
                send_message(content=out)
                return out

        new_lines: List[str] = []
        if needs_content:
            for line in str(content).splitlines(True):
                new_lines.append(line if line.endswith("\n") else (line + "\n"))

        if action == "add":
            insert_at = max(0, min(start - 1, total_lines))
            updated = lines[:insert_at] + new_lines + lines[insert_at:]
        elif action == "delete":
            updated = lines[: start - 1] + lines[end:]
        elif action == "update":
            updated = lines[: start - 1] + new_lines + lines[end:]
        else:
            out = f"不支持的 action: {action}"
            send_message(content=out)
            return out

        parent_dir = os.path.dirname(abs_path)
        try:
            os.makedirs(parent_dir, exist_ok=True)
        except Exception as e:
            out = f"创建目录失败 '{parent_dir}': {e}"
            send_message(content=out)
            return out

        try:
            with open(abs_path, "w", encoding="utf-8") as fw:
                fw.writelines(updated)
        except (IOError, OSError) as e:
            out = f"无法写入文件 '{abs_path}': {e}"
            send_message(content=out)
            return out

        out = (
            f"已应用 {action} 到 {relpath}: start={start}, end={end}, "
            f"new_lines={len(new_lines) if needs_content else 0}, old_lines={total_lines}, new_total={len(updated)}"
        )
        send_message(content=out)
        return out

    def parse_gcc_errors(input_str: str) -> str:
        cleaned = clear_quote(input_str).strip()
        if not cleaned:
            out = '请提供 C 文件，例如 {"file": "1.c"}。'
            send_message(content=out)
            return out

        payload: dict = {}
        if cleaned.startswith("{"):
            try:
                payload = json.loads(cleaned)
            except json.JSONDecodeError:
                try:
                    payload = ast.literal_eval(cleaned)
                except Exception as exc:
                    out = f"无法解析 JSON/dict 输入: {exc}"
                    send_message(content=out)
                    return out

        if not payload:
            tokens = cleaned.split()
            if tokens:
                payload["file"] = tokens[0]
                idx = 1
                while idx < len(tokens):
                    flag = tokens[idx]
                    if flag == "-l" and idx + 1 < len(tokens):
                        payload["line"] = tokens[idx + 1]
                        idx += 2
                        continue
                    if flag == "-n" and idx + 1 < len(tokens):
                        payload["limit"] = tokens[idx + 1]
                        idx += 2
                        continue
                    idx += 1

        c_file = payload.get("file") or payload.get("filepath")
        if not c_file:
            out = '缺少 "file" 路径，请提供类似 {"file": "1.c"} 的输入。'
            send_message(content=out)
            return out

        abs_c_file = os.path.join(base_dir, c_file)
        if not os.path.exists(abs_c_file):
            out = f"未找到 C 文件: {abs_c_file}"
            send_message(content=out)
            return out

        try:
            compile_proc = subprocess.run(
                ["gcc", "-c", "-w", "-fmax-errors=0", c_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding="utf-8",
                text=True,
                errors="ignore",
                cwd=base_dir,
            )
        except Exception as exc:
            out = f"运行 gcc 失败: {exc}"
            send_message(content=out)
            return out

        compiler_output = f"{compile_proc.stderr}\n{compile_proc.stdout}"
        send_message(content=f"[gcc 输出]\n{compiler_output}")
        lines = compiler_output.splitlines()

        try:
            errors = parse_gcc_error_lines(lines)
        except Exception as exc:
            combined = compiler_output.strip() or "无编译器输出。"
            out = f"解析 GCC 错误失败: {exc}\n编译器输出:\n{combined}"
            send_message(content=out)
            return out

        line_filter = payload.get("line")
        if line_filter is not None:
            try:
                target_line = int(str(line_filter).strip())
            except (ValueError, TypeError):
                out = "line 过滤条件必须是整数。"
                send_message(content=out)
                return out
            errors = [err for err in errors if err["line"] == target_line]
            if not errors:
                out = f"第 {target_line} 行未发现错误。"
                send_message(content=out)
                return out

        limit = payload.get("limit") or payload.get("n")
        if limit is not None:
            try:
                limit_val = int(str(limit).strip())
            except (ValueError, TypeError):
                out = "limit 必须是整数。"
                send_message(content=out)
                return out
            if limit_val <= 0:
                out = "limit 必须大于 0。"
                send_message(content=out)
                return out
            errors = errors[:limit_val]

        if not errors:
            if compile_proc.returncode == 0:
                out = "编译成功（Compilation succeeded），无错误。"
                send_message(content=out)
                return out
            combined = compiler_output.strip() or "无编译器输出。"
            out = f"未发现结构化错误。\n编译器输出:\n{combined}"
            send_message(content=out)
            return out

        result = "\n\n".join(format_gcc_error(err) for err in errors)
        result = truncate_text_by_tokens(result, TOOL_MAX_OUTPUT_TOKENS)
        send_message(content=result)
        return result

    return {
        "Terminal": ToolSpec(
            name="Terminal",
            func=terminal,
            description=(
                "在目标目录执行 shell 命令。\n"
                "输入：命令字符串。\n"
                "输出：stdout/stderr（可能被截断）。"
            ),
        ),
        "Read Code Slice": ToolSpec(
            name="Read Code Slice",
            func=read_code_slice,
            description=(
                "读取文件指定行附近的切片（行号从 1 开始）。\n"
                '输入 JSON/dict: {"filepath": "...", "line": 123, "context": 8}。\n'
                "输出：带行号的切片（可能被截断）。"
            ),
        ),
        "Patch Apply": ToolSpec(
            name="Patch Apply",
            func=patch_apply,
            description=(
                "对文件应用基于行的补丁。\n"
                '输入 JSON/dict: {"filepath":"...", "action":"add|delete|update", "start":1, "end":1, "content":"..."}。\n'
                "输出：简短状态字符串。"
            ),
        ),
        "Parse GCC Errors": ToolSpec(
            name="Parse GCC Errors",
            func=parse_gcc_errors,
            description=(
                "对 C 文件运行 `gcc -c -w -fmax-errors=0` 并返回格式化诊断。\n"
                '输入 JSON/dict: {"file":"1.c", "line": 12, "limit": 5} 或命令式 "1.c -l 12 -n 5"。\n'
                "输出：格式化错误或成功消息（可能被截断）。"
            ),
        ),
    }


# ---- small parsing / response helpers ----

def _format_tool_catalog(tools: Dict[str, ToolSpec]) -> str:
    return "\n".join(f"- {name}: {spec.description}" for name, spec in tools.items())

def _best_effort_json_extract(text: str) -> Optional[dict]:
    text = text.strip()
    if not text:
        return None
    if text.startswith("{") and text.endswith("}"):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None

def _parse_react_response(text: str) -> Tuple[str, str, Any, Optional[str]]:
    payload = _best_effort_json_extract(text)
    if payload is not None and isinstance(payload, dict):
        thought = str(payload.get("thought", "")).strip()
        action = str(payload.get("action", "")).strip()
        action_input = payload.get("action_input", "")
        final_answer = payload.get("final")
        if final_answer is not None:
            final_answer = str(final_answer)
        return thought, action, action_input, final_answer

    thought = ""
    action = ""
    action_input_lines: List[str] = []
    final_lines: List[str] = []
    mode: Optional[str] = None

    for line in text.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if lower.startswith("thought:"):
            thought = stripped.split(":", 1)[1].strip()
            mode = None
            continue
        if lower.startswith("action:"):
            action = stripped.split(":", 1)[1].strip()
            mode = "action_input"
            continue
        if lower.startswith("action input:"):
            action_input_lines.append(stripped.split(":", 1)[1].lstrip())
            mode = "action_input"
            continue
        if lower.startswith("final:"):
            final_lines.append(stripped.split(":", 1)[1].lstrip())
            mode = "final"
            continue
        if mode == "action_input":
            action_input_lines.append(line)
        elif mode == "final":
            final_lines.append(line)

    action_input = "\n".join(action_input_lines).strip()
    final_answer = "\n".join(final_lines).strip() if final_lines else None
    return thought.strip(), action.strip(), action_input, final_answer

def call_llm(client: OpenAI, messages: List[Dict[str, str]], max_tokens: int) -> str:
    llm_config = config_manager.get_llm_config_for("repair_agent")
    resp = client.chat.completions.create(
        model=llm_config["model_name"],
        messages=messages,
        temperature=0,
        max_tokens=max_tokens,
    )
    return resp.choices[0].message.content or ""

def _sanitize_log_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (dict, list)):
        try:
            json.dumps(value, ensure_ascii=False)
            return value
        except TypeError:
            return str(value)
    return str(value)

def _status_from_output(output: str) -> str:
    if not output:
        return "failure"
    lowered = output.lower()
    if "compilation succeeded" in lowered or "编译成功" in output:
        return "success"
    return "failure"

# ---- RepairReActAgent  ----

class RepairReActAgent:
    def __init__(
        self,
        # llm: ChatOpenAI,
        llm: OpenAI,
        tools: Dict[str, ToolSpec],
        base_dir: str,
        send_message: Callable[..., None],
        max_context_tokens: int = MAX_CONTEXT_WINDOW,
        max_iterations: int = 250,
        max_recent_steps_count: int = DEFAULT_RECENT_STEPS_COUNT,
        max_recent_steps_overflow_count: int = DEFAULT_RECENT_STEPS_OVERFLOW_COUNT,
        summary_max_lines: int = DEFAULT_SUMMARY_MAX_LINES,
        summary_render_lines: int = DEFAULT_SUMMARY_RENDER_LINES,
        summary_keep_on_overflow: int = DEFAULT_SUMMARY_KEEP_ON_OVERFLOW,
        verbose: bool = True,
    ):
        self.llm = llm
        self.tools = tools
        self.base_dir = base_dir
        self.max_context_tokens = max_context_tokens
        self.max_iterations = max_iterations
        self.max_recent_steps_count = max(1, int(max_recent_steps_count))
        self.max_recent_steps_overflow_count = max(1, int(max_recent_steps_overflow_count))
        if self.max_recent_steps_overflow_count > self.max_recent_steps_count:
            self.max_recent_steps_overflow_count = self.max_recent_steps_count
        self.summary_max_lines = max(1, int(summary_max_lines))
        self.summary_render_lines = max(1, int(summary_render_lines))
        self.summary_keep_on_overflow = max(1, int(summary_keep_on_overflow))
        if self.summary_keep_on_overflow > self.summary_max_lines:
            self.summary_keep_on_overflow = self.summary_max_lines

        self.send_message = send_message
        self.verbose = verbose

        self.summary_lines: List[str] = []
        self.recent_steps: List[Dict[str, Any]] = []

    def _shorten(self, text: str, max_tokens: int) -> str:
        return truncate_text_by_tokens(text, max_tokens).strip()

    def _rollup_old_steps(self, keep_last: Optional[int] = None) -> None:
        keep_last_steps = self.max_recent_steps_count if keep_last is None else max(1, int(keep_last))
        if len(self.recent_steps) <= keep_last_steps:
            return
        old = self.recent_steps[:-keep_last_steps]
        self.recent_steps = self.recent_steps[-keep_last_steps:]
        # summarize old steps
        for step in old:
            action = step.get("action", "")
            action_input = step.get("action_input", "")
            obs = step.get("observation", "")
            action_input_str = (
                action_input if isinstance(action_input, str) else json.dumps(action_input, ensure_ascii=False)
            )
            line = (
                f"{action}({self._shorten(action_input_str, 64)}) -> {self._shorten(str(obs), 96)}"
            )
            self.summary_lines.append(line)

        if len(self.summary_lines) > self.summary_max_lines:
            self.summary_lines = self.summary_lines[-self.summary_max_lines:]

    def _render_context(self, task: str) -> str:
        c_files = [f for f in os.listdir(self.base_dir) if f.lower().endswith(".c")]
        c_files.sort()

        summary = (
            "\n".join(f"- {line}" for line in self.summary_lines[-self.summary_render_lines:])
            if self.summary_lines
            else "(无)"
        )

        steps: List[str] = []
        for idx, step in enumerate(self.recent_steps[-self.max_recent_steps_count:], start=1):
            action_input = step.get("action_input", "")
            action_input_str = (
                action_input if isinstance(action_input, str) else json.dumps(action_input, ensure_ascii=False)
            )
            action = step.get("action", "")
            obs = str(step.get("observation", ""))
            if action == "Read Code Slice" or action == "Terminal":
                obs_display = obs
            else:
                obs_display = self._shorten(obs, MAX_PER_HISTORY_MESSAGE_TOKENS)

            steps.append(
                "\n".join(
                    [
                        f"[步骤 {idx}]",
                        f"执行工具: {action}",
                        f"执行参数: {self._shorten(action_input_str, 256)}",
                        f"执行结果: {obs_display}",
                    ]
                )
            )
        recent = "\n\n".join(steps) if steps else "(无)"

        return f"""{task.strip()}

目标目录: {self.base_dir}
目录中的 C 文件: {", ".join(c_files) if c_files else "(未找到)"}

可用工具:
{_format_tool_catalog(self.tools)}

记忆摘要（已汇总）:
{summary}

最近工具步骤:
{recent}

现在决定下一步。
仅返回严格 JSON，格式如下：

1) 调用工具:
{{
  "thought": "...",
  "action": "<one of the tool names above>",
  "action_input": "<string or object>"
}}

2) 结束:
{{
  "thought": "...",
  "action": "FINAL",
  "final": "说明你改了什么以及最新的编译结果。"
}}
"""

    def _build_messages(self, task: str, last_error: Optional[str] = None) -> List[Dict[str, str]]:
        system = (
            "你是一个 ReAct 风格的代理，用于修复 IDA 反编译的 C 伪代码使其可编译。\n"
            "你必须保持修改最小化，绝不能改变程序逻辑。\n"
            "不得新增/删除函数参数，不得删除或注释掉任何函数或逻辑。\n"
            "优先使用 `Parse GCC Errors` + `Read Code Slice` + `Patch Apply`，避免整文件输出。\n"
            "每次补丁后都要重新编译，直到成功。\n"
            "修改代码时，在修改行添加 C 注释 `// Modified: <reason>`。\n"
        )
        user = self._render_context(task)
        if last_error:
            user = f"{user}\n\n上一次响应有错误: {last_error}\n请仅返回有效 JSON。"
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]

        while True:
            token_count = sum(len(enc.encode(m["content"])) for m in messages)
            if token_count <= self.max_context_tokens:
                return messages

            # compress context progressively
            self._rollup_old_steps(keep_last=self.max_recent_steps_overflow_count)
            if self.summary_lines:
                self.summary_lines = self.summary_lines[-self.summary_keep_on_overflow:]
            if self.recent_steps:
                for step in self.recent_steps:
                    step["observation"] = self._shorten(str(step.get("observation", "")), 256)

            user = self._render_context(task)
            if last_error:
                user = f"{user}\n\n上一次响应有错误: {last_error}\n请仅返回有效 JSON。"
            messages[1] = {"role": "user", "content": user}

    def run(self, task: str) -> Dict[str, Any]:
        last_parse_error: Optional[str] = None

        for iteration in range(1, self.max_iterations + 1):
            self._rollup_old_steps()
            messages = self._build_messages(task, last_error=last_parse_error)
            last_parse_error = None

            # send current prompt context size info (brief)
            try:
                token_count = sum(token_len(m["content"]) for m in messages)
                # self.send_message(content=f"[iteration {iteration}] context={_fmt_token_usage(token_count, self.max_context_tokens)}")
            except Exception:
                pass

            response = call_llm(self.llm, messages, max_tokens=LLM_MAX_OUTPUT_TOKENS)
            thought, action, action_input, final_answer = _parse_react_response(response)

            # send LLM thought/action to websocket
            if thought:
                self.send_message(content=f"[思考]\n{thought}")
            if action:
                self.send_message(content=f"[执行工具]\n{action}")

            if not action:
                last_parse_error = "缺少 `action`。"
                self.send_message(content=f"[解析错误] {last_parse_error}")
                continue

            if action.upper() == "FINAL":
                final = (final_answer or response).strip()
                self.send_message(content=f"[最终答复]\n{final}")
                return {
                    "output": final,
                    "status": _status_from_output(final),
                }

            tool = self.tools.get(action)
            if tool is None:
                last_parse_error = f"未知工具: {action}。可用工具: {', '.join(self.tools)}"
                self.send_message(content=f"[解析错误] {last_parse_error}")
                continue

            if isinstance(action_input, (dict, list)):
                tool_input_str = json.dumps(action_input, ensure_ascii=False)
            else:
                tool_input_str = str(action_input)

            # send action_input
            self.send_message(content=f"[执行参数]\n{_safe_preview(tool_input_str, PRINT_MAX_MESSAGE_TOKENS)}")

            try:
                observation = tool.func(tool_input_str)
            except Exception as exc:
                observation = f"工具执行失败: {exc}\n{traceback.format_exc()}"

            # send observation
            self.send_message(content=f"[执行结果]\n{_safe_preview(observation, PRINT_MAX_OBSERVATION_TOKENS)}")

            # record recent step
            self.recent_steps.append(
                {
                    "thought": thought,
                    "action": action,
                    "action_input": action_input,
                    "observation": observation,
                }
            )

            if (
                "Compilation succeeded" in (observation or "")
                or "compilation succeeded" in (observation or "").lower()
                or "编译成功" in (observation or "")
            ):
                return {
                    "output": "编译成功（Compilation succeeded）。",
                    "status": "success",
                }

        return {
            "output": f"达到最大迭代次数 ({self.max_iterations})，仍未完成。",
            "status": "failure",
        }

# ---- run_repair_agent  ----

def run_repair_agent(base_dir: str, websocket_sender: Callable[..., None]):
    """
    在 base_dir 上运行修复代理，使用 websocket_sender(content=...) 流式发送消息。
    成功返回 (True, "修复完成")，失败返回 (False, error_msg)。
    """
    try:
        llm_config = config_manager.get_llm_config_for("repair_agent")
        llm = OpenAI(api_key=llm_config["api_key"], base_url=llm_config["base_url"])

        # build tools with websocket sender
        tools = build_tools(base_dir, websocket_sender)

        # question / instruction in Chinese (与 earlier v2 保持一致语义)
        question = """\
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

        # send start info to websocket
        websocket_sender(content=f"开始处理目录: {base_dir}")

        agent = RepairReActAgent(
            llm=llm,
            tools=tools,
            base_dir=base_dir,
            send_message=websocket_sender,
            max_iterations=1000,
            max_context_tokens=MAX_CONTEXT_WINDOW,
            verbose=True,
        )

        result = agent.run(question)
        # store result to llm_result.json in base_dir
        save_llm_result(base_dir, result=result, extra_log="repair_agent_v2_with_websocket run")
        websocket_sender(content=f"[结果] 状态={result.get('status')}, 信息={result.get('output')}")

    except Exception as e:
        tb_str = traceback.format_exc()
        save_llm_result(base_dir, result=None, error=e, tb_str=tb_str, extra_log="repair_agent_v2_with_websocket error")
        websocket_sender(content=f"[错误] {e}\n{tb_str}")
        return False, f"{str(e)}"

    return True, "修复完成"


# ---- if run as script: provide fallback websocket_sender that prints to stdout ----
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="在指定目录运行修复代理（websocket 版本）。")
    parser.add_argument(
        "-d",
        "--directory",
        type=str,
        default=os.getcwd(),
        help="指定要处理的目录（默认：当前目录）",
    )
    args = parser.parse_args()

    base_dir = os.path.abspath(args.directory)

    def _print_sender(**kwargs):
        # expected signature: send_message(content=...)
        content = kwargs.get("content")
        print(content)

    run_repair_agent(base_dir, _print_sender)
