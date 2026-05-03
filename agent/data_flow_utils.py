"""Utilities for formatting high-risk parameter data-flow chains from IDA call info."""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)

HIGH_RISK_SOURCES = {"http_header", "network_socket", "user_input", "file_read"}
CONTROLLABLE_TYPES = {"http_header", "network_socket", "user_input"}
MAX_TRACE_DEPTH = 6

HTTP_HEADER_PAT = re.compile(r"\bHTTP_|http_header|websGet", re.IGNORECASE)
SOCKET_PAT = re.compile(r"\brecv\s*\(|\bread\s*\(|socket_read", re.IGNORECASE)
FILE_PAT = re.compile(r"\bfopen\s*\(|fgets\s*\(|fread\s*\(", re.IGNORECASE)
USER_INPUT_PAT = re.compile(r"\bgets\b|\bscanf\b|\bfgets\b", re.IGNORECASE)
ENV_PAT = re.compile(r"\bgetenv\s*\(", re.IGNORECASE)


def _short(text: Optional[str], limit: int = 200) -> str:
    if not text:
        return ""
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + "..."


def _classify_source_stmt(text: Optional[str]) -> str:
    if not text:
        return ""
    if HTTP_HEADER_PAT.search(text):
        return "http_header"
    if SOCKET_PAT.search(text):
        return "network_socket"
    if USER_INPUT_PAT.search(text):
        return "user_input"
    if FILE_PAT.search(text):
        return "file_read"
    if ENV_PAT.search(text):
        return "environment"
    return ""


def _extract_func_name(text: Optional[str]) -> str:
    if not text:
        return ""
    match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", text)
    return match.group(1) if match else ""


def _dedup_chain(chain: Sequence[str]) -> List[str]:
    deduped: List[str] = []
    for item in chain:
        if not deduped or deduped[-1] != item:
            deduped.append(item)
    return deduped


def _format_param_origins(origins: Sequence[Dict[str, Any]]) -> str:
    items = []
    for origin in origins:
        idx = origin.get("index")
        name = origin.get("name") or (f"arg{idx}" if idx is not None else "?")
        if idx is None:
            items.append(name)
        else:
            items.append(f"{name}(arg{idx})")
    return ", ".join(items)


def _format_cross_path(path: Sequence[Dict[str, Any]]) -> str:
    if not path:
        return ""
    segments: List[str] = []
    start = path[0]
    start_func = start.get("function_name") or "<unknown>"
    start_param = start.get("param_name") or (
        f"arg{start.get('param_index')}" if start.get("param_index") is not None else "arg?"
    )
    segments.append(f"{start_func}::{start_param}")

    for step in path[1:]:
        fname = step.get("function_name") or "<unknown>"
        arg_expr = _short(step.get("arg_expr"))
        ctype = ((step.get("arg_classification") or {}).get("type")) or "unknown"
        part = f"<- {fname}({arg_expr})[{ctype}]"
        call_text = _short(step.get("call_text"))
        if call_text:
            part += f" @ {call_text}"
        segments.append(part)

    return " ".join(segments)


def _trace_sources(
    var_name: Optional[str],
    backward_flow: Dict[str, Any],
    depth: int = 0,
    chain: Optional[List[str]] = None,
    seen: Optional[set] = None,
) -> List[Dict[str, Any]]:
    if depth > MAX_TRACE_DEPTH:
        return []
    if not re.match(r"^[A-Za-z_]\w*$", var_name or ""):
        return []

    entries = backward_flow.get(var_name or "", []) or []
    if not entries:
        return []

    chain = (chain or []) + [var_name]
    seen = set(seen or ())
    results: List[Dict[str, Any]] = []

    for entry in entries:
        use_text = entry.get("use_stmt_text")
        slices = entry.get("slices", []) or []
        for sl in slices:
            def_stmt = (sl or {}).get("def_stmt") or {}
            defined_var = (sl or {}).get("var") or var_name
            def_text = def_stmt.get("text") or ""
            stmt_key = (defined_var, def_stmt.get("raw_line_idx"))
            if stmt_key in seen:
                continue

            classification = _classify_source_stmt(def_text)
            next_chain = chain + ([defined_var] if defined_var not in chain else [])
            record = {
                "source_var": defined_var,
                "source_stmt": def_text,
                "source_type": classification,
                "source_func": _extract_func_name(def_text),
                "use_stmt": use_text,
                "path": next_chain,
            }

            if classification in HIGH_RISK_SOURCES:
                record["controllable"] = classification in CONTROLLABLE_TYPES
                results.append(record)
                continue

            upstream_vars = [v for v in (def_stmt.get("uses") or []) if v != defined_var]
            if not upstream_vars:
                continue
            new_seen = set(seen)
            new_seen.add(stmt_key)
            for upstream in upstream_vars:
                results.extend(
                    _trace_sources(
                        upstream,
                        backward_flow,
                        depth + 1,
                        next_chain + [upstream],
                        new_seen,
                    )
                )
    return results


def format_key_param_data_flow(call_info: Dict[str, Any]) -> str:
    """Format key parameter data-flow chains identical to the Refiner helper."""
    if not isinstance(call_info, dict) or not call_info:
        return ""

    lines: List[str] = []
    func = call_info.get("function", {}) or {}
    fname = func.get("name") or call_info.get("function_name")
    if fname:
        lines.append(f"[函数] {fname}")

    df = call_info.get("data_flow", {}) or {}
    backward_flow = df.get("backward_flow", {}) or {}

    chains = call_info.get("chains", []) or []
    logger.debug("format_key_param_data_flow: sinks=%s", len(chains))

    for sink in chains:
        callee = sink.get("callee")
        snippet = sink.get("snippet")
        args = sink.get("args", []) or []

        if callee:
            lines.append(f"[Sink] {callee}")
        if snippet:
            lines.append(f"  代码片段: {_short(snippet)}")

        for arg in args:
            arg_text = (arg or {}).get("text", "")
            arg_idx = (arg or {}).get("arg_index")
            classification = ((arg or {}).get("classification") or {}).get("type", "")

            is_key = classification in HIGH_RISK_SOURCES
            origin_types = set()
            for chain in (arg or {}).get("chains", []) or []:
                rhs = (chain or {}).get("rhs_class") or {}
                origin = (chain or {}).get("origin") or {}
                if isinstance(rhs, dict):
                    t = rhs.get("type")
                    if t:
                        origin_types.add(t)
                if isinstance(origin, dict):
                    t = origin.get("type")
                    if t:
                        origin_types.add(t)
            if origin_types & HIGH_RISK_SOURCES:
                is_key = True

            if not is_key:
                continue

            header = f"  [关键参数] arg{arg_idx}: {arg_text} ({classification or 'unknown'})"
            if origin_types:
                header += f" | 溯源: {', '.join(sorted(origin_types))}"
            lines.append(header)

            param_origins = (arg or {}).get("param_origins") or []
            if param_origins:
                lines.append(f"    入参映射: {_format_param_origins(param_origins)}")

            var_name = arg_text.strip()
            source_infos = _trace_sources(var_name, backward_flow)
            if source_infos:
                for idx_src, src in enumerate(source_infos[:5], 1):
                    src_type = src.get("source_type") or "unknown"
                    controllable = src.get("controllable", False)
                    func_name = src.get("source_func") or "-"
                    lines.append(
                        f"    [SourceChain#{idx_src}] 类型: {src_type} | 函数: {func_name} | 可控: {'是' if controllable else '否'}"
                    )
                    lines.append(f"      Source语句: {_short(src.get('source_stmt'))}")
                    if src.get("use_stmt"):
                        lines.append(f"      紧邻使用: {_short(src.get('use_stmt'))}")
                    chain_vars = _dedup_chain(src.get("path") or [])
                    if chain_vars:
                        chain_summary = " -> ".join(reversed(chain_vars))
                        lines.append(f"      传播链: {chain_summary}")
            else:
                lines.append("    [SourceChain] 未从逆向切片中找到可控来源")

            for chain in (arg or {}).get("chains", []) or []:
                rhs = (chain or {}).get("rhs_class") or {}
                detail = rhs.get("detail") if isinstance(rhs, dict) else None
                if detail:
                    lines.append(f"    溯源片段: {_short(detail)}")

            cross_paths = (arg or {}).get("cross_function_paths") or []
            if cross_paths:
                for cp_idx, cross in enumerate(cross_paths, 1):
                    pname = cross.get("param_name") or (
                        f"arg{cross.get('param_index')}" if cross.get("param_index") is not None else "arg?"
                    )
                    lines.append(
                        f"    [跨函数溯源#{cp_idx}] 起点: {pname}"
                    )
                    for path_idx, path in enumerate(cross.get("paths") or [], 1):
                        summary = _format_cross_path(path)
                        if summary:
                            lines.append(f"      路径{path_idx}: {summary}")
                        else:
                            lines.append(f"      路径{path_idx}: <空>")

    if len(lines) <= (1 if fname else 0):
        if fname:
            lines.append("[提示] 未检测到关键 sink 或可追踪参数，可能需要扩展 SINK 关键字或重新运行 IDA 分析")
            return "\n".join(lines)
        return ""

    text = "\n".join(lines)
    logger.debug("关键参数数据流上下文长度: %s", len(text))
    return text


def format_vuln_context(call_info: Dict[str, Any]) -> str:
    """
    Format the vulnerability context according to the new requirements:
    1. Function Call Chain (Tree/Arrow)
    2. Key Parameter Data Flow (Table)
    3. Control Flow Critical Paths
    """
    if not isinstance(call_info, dict) or not call_info:
        return "No context available (Analysis data is empty or failed to load)."

    lines = []
    
    # 1. Function Call Chain
    lines.append("1️⃣ 函数调用链 (Call Chain)")
    root_func = call_info.get("function", {}).get("name", "Target")
    
    # Try to build a simple chain from the callers dict
    # This is a simplification; a real tree requires better structure from analyze.py
    callers = call_info.get("callers", {})
    if not callers:
        lines.append(f"Target: {root_func} (No callers found)")
    else:
        # Flatten unique callers for display
        unique_callers = set()
        for ea, caller_list in callers.items():
            # caller_list is a dict in analyze.py: {"name": ..., "calls": ...}
            # Wait, in analyze.py: callers_named[c_ea] = {"name": ..., "calls": ...}
            # So callers is Dict[int, Dict]
            # The previous code iterated callers.items() -> ea, caller_list (which is the dict)
            # But the loop `for c in caller_list:` implies caller_list is a list.
            # Let's check analyze.py again.
            # analyze.py: callers = find_callers(...) -> Dict[int, List[Dict]]
            # analyze.py: callers_named[c_ea] = {"name": ..., "calls": calllist}
            # So callers in json is Dict[str(ea), Dict] where Dict has "calls": List
            
            # Correct logic for flattened callers:
            c_name = caller_list.get("name", f"sub_{ea}")
            unique_callers.add(c_name)
        
        if unique_callers:
            chain_str = " -> ".join(sorted(unique_callers)) + f" -> {root_func}"
            lines.append(chain_str)
        else:
            lines.append(f"Target: {root_func}")
    lines.append("")

    # 2. Key Parameter Data Flow
    lines.append("2️⃣ 关键参数的数据流 (Data Flow)")
    lines.append("| 步骤 | 函数名 | 参数/变量 | 来源 | 中间处理 | 风险说明 |")
    lines.append("|---|---|---|---|---|---|")
    
    chains = call_info.get("chains", [])
    backward_flow = call_info.get("data_flow", {}).get("backward_flow", {})
    step_count = 1
    
    for sink in chains:
        callee = sink.get("callee", "unknown")
        args = sink.get("args", [])
        
        for arg in args:
            arg_text = arg.get("text", "")
            var_name = arg_text.strip()
            
            # Trace sources using existing logic
            source_infos = _trace_sources(var_name, backward_flow)
            
            if not source_infos:
                # If no source found, just list the sink usage
                lines.append(f"| {step_count} | {root_func} | {arg_text} | Unknown | - | Potential Sink ({callee}) |")
                step_count += 1
                continue

            for src in source_infos:
                source_type = src.get("source_type", "unknown")
                source_func = src.get("source_func", root_func)
                source_stmt = _short(src.get("source_stmt"), 40).replace("|", "\\|")
                risk = "High" if src.get("controllable") else "Low"
                
                # Source step
                lines.append(f"| {step_count} | {source_func} | {src.get('source_var')} | {source_type} | {source_stmt} | {risk} |")
                step_count += 1
                
                # Propagation steps (simplified)
                path = src.get("path", [])
                if len(path) > 1:
                    for i in range(len(path)-1):
                        p_var = path[i]
                        next_var = path[i+1]
                        lines.append(f"| {step_count} | {root_func} | {next_var} | {p_var} | Propagation | - |")
                        step_count += 1

            # Final sink step
            lines.append(f"| {step_count} | {root_func} | {arg_text} | {var_name} | Passed to {callee} | Sink Trigger |")
            step_count += 1

    lines.append("")

    # 3. Control Flow Critical Paths
    lines.append("3️⃣ 控制流关键路径 (Control Flow)")
    # Check if we have control flow info (to be added in analyze.py)
    control_flow = call_info.get("control_flow", [])
    if control_flow:
        for idx, path in enumerate(control_flow, 1):
            lines.append(f"Path {idx}: {path}")
    else:
        lines.append("(No control flow paths identified)")
    
    return "\n".join(lines)

__all__ = ["format_key_param_data_flow", "format_vuln_context"]
