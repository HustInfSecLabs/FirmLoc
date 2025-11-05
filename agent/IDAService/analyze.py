"""
IDA Binary Analysis Tool
分析二进制程序的数据流、控制流和调用链
"""
from __future__ import annotations
import idaapi, idautils, idc, ida_hexrays, ida_nalt
import re, json, os, sys, argparse
from typing import List, Dict, Any, Optional
import logging
from datetime import datetime

def setup_logger():
    """设置日志记录器"""
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "log")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"{datetime.now().strftime('%Y%m%d')}-analyze.log")
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logger()

# 配置常量
SINK_KEYWORDS = [
    "system", "popen", "execl", "execv", "execve", "CreateProcessA", "CreateProcessW",
    "sprintf", "vsprintf", "strcpy", "strncpy", "fopen", "fgets"
]
MAX_CALLER_DEPTH = 4

def get_output_dir():
    """获取输出目录"""
    try:
        bin_path = ida_nalt.get_input_file_path()
        if bin_path and os.path.exists(os.path.dirname(bin_path)):
            return os.path.dirname(bin_path)
    except:
        pass
    
    # 默认使用脚本目录
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(script_dir, "ida_output", datetime.now().strftime('%Y%m%d'))
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

# 初始化Hex-Rays
USE_HEXRAYS = False
try:
    USE_HEXRAYS = ida_hexrays.init_hexrays_plugin()
    logger.info(f"Hex-Rays插件状态: {'成功' if USE_HEXRAYS else '失败'}")
except Exception as e:
    logger.error(f"Hex-Rays插件初始化异常: {str(e)}")

# 正则表达式模式
ENV_PAT = re.compile(r'\bgetenv\s*\(')
HTTP_HEADER_PAT = re.compile(r'\bHTTP_|http_header|websGet', re.IGNORECASE)
SOCKET_PAT = re.compile(r'\brecv\s*\(|\bread\s*\(|socket_read', re.IGNORECASE)
FILE_READ_PAT = re.compile(r'\bfopen\s*\(|fgets\s*\(|fread\s*\(', re.IGNORECASE)
USER_INPUT_PAT = re.compile(r'\bgets\b|\bscanf\b|\bfgets\b', re.IGNORECASE)
CONST_STR_PAT = re.compile(r'["\'][^"\']{0,200}["\']')
NUMERIC_LITERAL_PAT = re.compile(r'^[0-9xXa-fA-F]+$')
SAFE_CONSTANTS = ["/usr", "/etc", "/bin", "/sbin"]

# 工具函数
def get_func_name(ea: int) -> str:
    """获取函数名"""
    if hasattr(idc, "get_func_name"):
        return idc.get_func_name(ea) or ""
    return idc.GetFunctionName(ea) or ""

def decompile_text(ea: int) -> str:
    """反编译函数文本"""
    try:
        if USE_HEXRAYS:
            cfunc = ida_hexrays.decompile(ea)
            if cfunc is None:
                return decompile_fallback(ea)
            
            # 清理IDA内部标记
            raw_text = str(cfunc)
            cleaned_text = re.sub(r'\([0-9a-fA-F]{8,16}(?:\s|$)', ' ', raw_text)
            cleaned_text = re.sub(r'\s+', ' ', cleaned_text)
            cleaned_text = re.sub(r'\s*;\s*', ';\n', cleaned_text)
            cleaned_text = re.sub(r'\s*{\s*', '{\n', cleaned_text)
            cleaned_text = re.sub(r'\s*}\s*', '\n}\n', cleaned_text)
            return cleaned_text
        else:
            return decompile_fallback(ea)
    except Exception as e:
        logger.warning(f"反编译失败: {str(e)}")
        return decompile_fallback(ea)

def decompile_fallback(ea: int) -> str:
    """反编译fallback方法"""
    try:
        fn = get_func_name(ea)
        cmt = idc.get_func_cmt(ea, True) or ""
        text = fn + "\n" + cmt
        
        start = idc.get_func_attr(ea, idc.FUNCATTR_START)
        end = idc.get_func_attr(ea, idc.FUNCATTR_END)
        if start and end:
            asm_lines = []
            for head in idautils.Heads(start, end):
                asm_lines.append(idc.generate_disasm_line(head))
            text += "\n" + "\n".join(asm_lines)
        
        return text
    except Exception as e:
        return "// fallback decompile failed: " + str(e)

def find_sinks_in_text(text: str) -> List[Dict[str,Any]]:
    """查找文本中的sink函数调用"""
    sinks = []
    for kw in SINK_KEYWORDS:
        pat = re.compile(r'\b' + re.escape(kw) + r'\s*\((.*?)\)', re.S)
        for m in pat.finditer(text):
            snippet = text[max(0, text.rfind('\n', 0, m.start())+1):text.find('\n', m.end())].strip()
            args = split_args_top_level(m.group(1))
            sinks.append({"callee": kw, "snippet": snippet, "args_raw": args, "pos": m.start()})
    return sinks

def split_args_top_level(argstr: str) -> List[str]:
    """分割函数参数"""
    parts = []
    cur = ""
    depth = 0
    for ch in argstr:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        if ch == ',' and depth == 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur.strip())
    return parts

def classify_expr(expr: str) -> Dict[str,Any]:
    """表达式源类型分类"""
    if not expr:
        return {"type":"unknown", "detail":None}
    
    if ENV_PAT.search(expr):
        return {"type":"environment", "detail":expr}
    if HTTP_HEADER_PAT.search(expr):
        return {"type":"http_header", "detail":expr}
    if SOCKET_PAT.search(expr):
        return {"type":"network_socket", "detail":expr}
    if FILE_READ_PAT.search(expr):
        return {"type":"file_read", "detail":expr}
    if USER_INPUT_PAT.search(expr):
        return {"type":"user_input", "detail":expr}
    
    if CONST_STR_PAT.search(expr) and not re.search(r'\+\s*', expr):
        lit = CONST_STR_PAT.search(expr).group(0)
        for s in SAFE_CONSTANTS:
            if s in lit:
                return {"type":"constant_safe_path", "detail":lit}
        return {"type":"constant_literal", "detail":lit}
    
    if NUMERIC_LITERAL_PAT.match(expr.strip()):
        return {"type":"constant_numeric", "detail":expr.strip()}
    
    # 函数调用
    m = re.match(r'([A-Za-z_][A-Za-z0-9_]*)\s*\(', expr)
    if m:
        return {"type":"function_return", "detail":m.group(1)}
    
    # 变量
    if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', expr.strip()):
        return {"type":"variable", "detail":expr.strip()}
    
    # 复合表达式
    if '+' in expr or 'strcat' in expr or 'sprintf' in expr:
        return {"type":"composite", "detail":expr}
    
    return {"type":"unknown", "detail":expr}

def find_callers(func_ea: int, max_depth: int = MAX_CALLER_DEPTH) -> Dict[int, List[Dict[str,Any]]]:
    """查找函数调用者"""
    res = {}
    seen_funcs = set()
    
    def walk(ea, depth):
        if depth > max_depth:
            return
        for xr in idautils.XrefsTo(ea):
            call_ea = xr.frm
            caller_func = idaapi.get_func(call_ea)
            caller_ea = caller_func.start_ea if caller_func else None
            caller_name = get_func_name(caller_ea) if caller_ea else "<unknown>"
            
            call_text = ""
            args = []
            if caller_ea:
                txt = decompile_text(caller_ea)
                fname = get_func_name(ea)
                pattern = re.compile(re.escape(fname) + r'\s*\((.*?)\)', re.S)
                m = pattern.search(txt)
                if m:
                    args = split_args_top_level(m.group(1))
                    call_text = txt[max(0, txt.rfind('\n',0,m.start())+1):txt.find('\n', m.end())].strip()
                
            res.setdefault(caller_ea or 0, []).append({
                "call_ea": call_ea, 
                "call_text": call_text, 
                "args": args
            })
            
            if caller_ea and caller_ea not in seen_funcs:
                seen_funcs.add(caller_ea)
                walk(caller_ea, depth+1)
    
    walk(func_ea, 0)
    return res

# 文本分析和后向切片
def build_def_map_from_text(cfunc_text: str) -> List[Dict[str,Any]]:
    """解析反编译文本，构建语句定义和使用映射"""
    if len(cfunc_text) < 50:
        logger.warning(f"反编译文本过短: {len(cfunc_text)}")
        return []
    
    stmts = []
    lines = cfunc_text.splitlines()
    
    # 赋值模式
    assignment_patterns = [
        re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\])?)\s*=\s*(.+);\s*$'),  # 基本赋值
        re.compile(r'^\s*(?:(?:unsigned\s+)?(?:int|char|long|_DWORD|_BYTE)\s*\*?\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+);\s*$'),  # 声明赋值
        re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\])*?)\s*=\s*(.+);\s*$'),  # 数组赋值
    ]
    
    var_pattern = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\b')
    keywords_to_filter = {
        'if', 'else', 'while', 'for', 'return', 'int', 'char', 'long', 'unsigned',
        'void', 'const', 'static', 'printf', 'strlen', 'strcmp', 'malloc', 'free',
        'memcpy', 'sizeof', 'struct', 'goto', 'break', 'continue'
    }
    
    for i, line in enumerate(lines):
        text = line.strip()
        if not text or text.startswith('//') or text in ['{', '}']:
            continue
        
        defines = []
        uses = []
        
        # 匹配赋值语句
        matched = False
        for pattern in assignment_patterns:
            match = pattern.match(text)
            if match:
                lhs = match.group(1).strip()
                rhs = match.group(2).strip()
                
                var_name = re.sub(r'\[.*?\]', '', lhs).strip()
                if var_name and var_name not in keywords_to_filter:
                    defines.append(var_name)
                
                vars_found = var_pattern.findall(rhs)
                for v in vars_found:
                    if v not in keywords_to_filter and v not in defines:
                        uses.append(v)
                
                matched = True
                break
        
        if not matched:
            # 查找变量使用
            vars_found = var_pattern.findall(text)
            for v in vars_found:
                if v not in keywords_to_filter:
                    uses.append(v)
        
        stmts.append({
            "idx": len(stmts),
            "text": text,
            "defines": list(set(defines)),
            "uses": list(set(uses)),
            "raw_line_idx": i
        })
    
    total_defines = sum(len(stmt["defines"]) for stmt in stmts)
    logger.info(f"解析完成: {len(stmts)} 个语句，{total_defines} 个变量定义")
    return stmts

def backward_slice_on_var(stmts: List[Dict[str,Any]], use_stmt_idx: int, varname: str, max_hops=10) -> List[Dict[str,Any]]:
    """后向切片：从使用点向前查找变量定义"""
    chains = []
    visited = set()
    worklist = [(use_stmt_idx, varname, 0)]
    
    while worklist:
        stmt_idx, var, depth = worklist.pop(0)
        if depth > max_hops:
            continue
        
        for sidx in range(stmt_idx-1, -1, -1):
            s = stmts[sidx]
            if var in s["defines"]:
                chains.append({"def_stmt": s, "depth": depth, "var": var})
                for used in s["uses"]:
                    if used == var:
                        continue
                    key = (sidx, used)
                    if key in visited:
                        continue
                    visited.add(key)
                    worklist.append((sidx, used, depth+1))
                break
    
    return chains

# 主要分析函数
def analyze_function(func_ea: int) -> Dict[str,Any]:
    """分析函数的安全性"""
    fname = get_func_name(func_ea) or ("sub_%X" % func_ea)
    text = decompile_text(func_ea)
    
    # 查找sink函数
    sinks = find_sinks_in_text(text)
    
    # 构建语句映射
    stmts = build_def_map_from_text(text)
    
    # 查找调用者
    callers = find_callers(func_ea, MAX_CALLER_DEPTH)
    callers_named = {}
    for c_ea, calllist in callers.items():
        callers_named[c_ea] = {
            "name": get_func_name(c_ea) if c_ea else "<unknown>", 
            "calls": calllist
        }
    
    # 分析每个sink的参数链
    chains = []
    for sink in sinks:
        sink_info = {"callee": sink["callee"], "snippet": sink["snippet"], "args": []}
        
        for idx, arg in enumerate(sink["args_raw"]):
            cl = classify_expr(arg)
            arginfo = {"arg_index": idx, "text": arg, "classification": cl, "chains": []}
            
            # 对变量进行后向切片分析
            if cl["type"] in ("variable", "composite", "unknown"):
                # 查找使用该变量的语句位置
                use_stmt_idx = len(stmts) - 1  # 简化：假设在最后使用
                defs = backward_slice_on_var(stmts, use_stmt_idx, cl.get("detail") or arg)
                
                for d in defs:
                    dstmt = d["def_stmt"]
                    rcl = classify_expr(dstmt["text"])
                    arginfo["chains"].append({"defined_at": dstmt, "rhs_class": rcl})
            else:
                arginfo["chains"].append({"origin": cl})
            
            sink_info["args"].append(arginfo)
        chains.append(sink_info)
    
    # 风险评估
    assessments = []
    for sink in chains:
        callee = sink["callee"]
        for arg in sink["args"]:
            risk_info = assess_risk(arg, sink)
            risk_info["sink"] = callee
            risk_info["arg"] = arg["text"]
            assessments.append(risk_info)
    
    result = {
        "function": {"ea": func_ea, "name": fname},
        "sinks": sinks,
        "callers": callers_named,
        "chains": chains,
        "nl_assessments": assessments
    }
    
    return result

def assess_risk(arg_info: Dict, sink_info: Dict) -> Dict[str, str]:
    """评估风险等级"""
    origins = []
    for ch in arg_info["chains"]:
        if "origin" in ch:
            origins.append(ch["origin"])
        elif "rhs_class" in ch:
            origins.append(ch["rhs_class"])
    
    types = set([o.get("type", "") for o in origins if isinstance(o, dict)])
    
    if "environment" in types or "constant_literal" in types:
        return {"risk": "low", "confidence": "high", "reason": "来源为环境变量或常量"}
    elif "http_header" in types or "network_socket" in types or "user_input" in types:
        return {"risk": "high", "confidence": "medium", "reason": "来源为网络输入，可能被攻击者控制"}
    elif "file_read" in types:
        return {"risk": "medium", "confidence": "medium", "reason": "来源为文件读取，需判断文件是否可控"}
    else:
        return {"risk": "unknown", "confidence": "low", "reason": "无法确定来源"}

# 数据流分析
def forward_data_flow(func_ea: int) -> Dict[str, Any]:
    """前向数据流分析"""
    text = decompile_text(func_ea)
    stmts = build_def_map_from_text(text)
    
    if not stmts:
        return {}
    
    flow_info = {}
    
    # 收集变量定义
    var_defs = {}
    for idx, stmt in enumerate(stmts):
        for var in stmt["defines"]:
            if var not in var_defs:
                var_defs[var] = []
            var_defs[var].append(idx)
    
    # 追踪变量使用
    for var, def_indices in var_defs.items():
        uses = []
        for def_idx in def_indices:
            for use_idx in range(def_idx + 1, len(stmts)):
                if var in stmts[use_idx]["uses"]:
                    uses.append({
                        "stmt_idx": use_idx,
                        "stmt_text": stmts[use_idx]["text"],
                        "distance": use_idx - def_idx
                    })
        
        if uses:
            flow_info[var] = {
                "definitions": [stmts[idx]["text"] for idx in def_indices],
                "uses": uses
            }
    
    return flow_info

def get_complete_data_flow(func_ea: int) -> Dict[str, Any]:
    """获取完整数据流分析"""
    fname = get_func_name(func_ea) or ("sub_%X" % func_ea)
    
    # 前向数据流
    forward_flow = forward_data_flow(func_ea)
    
    # 后向数据流
    text = decompile_text(func_ea)
    stmts = build_def_map_from_text(text)
    backward_flow = {}
    
    if stmts:
        all_vars = set()
        for stmt in stmts:
            all_vars.update(stmt["defines"])
            all_vars.update(stmt["uses"])
        
        for var in all_vars:
            var_uses = []
            for stmt_idx, stmt in enumerate(stmts):
                if var in stmt["uses"]:
                    slices = backward_slice_on_var(stmts, stmt_idx, var)
                    if slices:
                        var_uses.append({
                            "use_stmt_idx": stmt_idx,
                            "use_stmt_text": stmt["text"],
                            "slices": slices
                        })
            
            if var_uses:
                backward_flow[var] = var_uses
    
    # 调用信息
    callers = find_callers(func_ea)
    callers_named = {}
    for c_ea, calllist in callers.items():
        callers_named[c_ea] = {
            "name": get_func_name(c_ea) if c_ea else "<unknown>", 
            "calls": calllist
        }
    
    # 被调用函数信息
    sinks = find_sinks_in_text(text)
    callees = []
    for sink in sinks:
        callees.append({
            "name": sink["callee"],
            "snippet": sink["snippet"],
            "args": sink["args_raw"]
        })
    
    return {
        "function": {"ea": func_ea, "name": fname},
        "forward_flow": forward_flow,
        "backward_flow": backward_flow,
        "callers": callers_named,
        "callees": callees
    }

# 等待IDA分析完成
idc.auto_wait()

def find_function_by_name(func_name: str) -> Optional[int]:
    """通过函数名查找函数地址"""
    func_name_lower = func_name.lower()
    
    # 精确匹配
    for func_ea in idautils.Functions():
        current_name = get_func_name(func_ea)
        if current_name == func_name or current_name.lower() == func_name_lower:
            return func_ea
    
    # 尝试IDA风格函数名
    if not func_name.startswith('sub_'):
        if re.match(r'^[0-9A-Fa-f]{6,}$', func_name):
            ida_style_name = 'sub_' + func_name
            for func_ea in idautils.Functions():
                current_name = get_func_name(func_ea)
                if current_name == ida_style_name or current_name.lower() == ida_style_name.lower():
                    return func_ea
    
    # 部分匹配
    for func_ea in idautils.Functions():
        current_name = get_func_name(func_ea)
        if func_name in current_name or func_name_lower in current_name.lower():
            return func_ea
    
    # 尝试解析为地址
    try:
        addr = int(func_name, 16) if not func_name.startswith('0x') else int(func_name, 16)
        func = idaapi.get_func(addr)
        if func:
            return addr
    except ValueError:
        pass
    
    return None

def main():
    """主程序入口"""
    logger.info("IDA函数安全分析工具启动")
    try:
        parser = argparse.ArgumentParser(description='IDA函数安全分析工具')
        parser.add_argument('--func', '-n', help='要分析的函数名')
        
        # 优先检查环境变量（最可靠的方式）
        func_name = os.environ.get('IDA_FUNC_NAME')
        if func_name:
            logger.info(f"从环境变量 IDA_FUNC_NAME 获取函数名: {func_name}")
        
        # 如果环境变量中没有，再尝试其他方式
        args = None
        
        try:
            import subprocess
            if os.name == 'nt':  # Windows系统
                # 使用wmic获取当前进程的命令行
                cmd = 'wmic process where ProcessId="%d" get CommandLine /format:list' % os.getpid()
                result = subprocess.check_output(cmd, shell=True, universal_newlines=True)
                full_cmd_line = result.replace('CommandLine=', '').strip()
                logger.info(f"获取到完整命令行: {full_cmd_line}")
                
                # 从完整命令行中提取参数
                if '-S' in full_cmd_line:
                    # 查找-S参数及其内容
                    s_param_start = full_cmd_line.find('-S')
                    if s_param_start != -1:
                        # 查找引号
                        quote_start = full_cmd_line.find('"', s_param_start)
                        if quote_start != -1:
                            quote_end = full_cmd_line.find('"', quote_start + 1)
                            if quote_end != -1:
                                s_content = full_cmd_line[quote_start + 1:quote_end]
                                logger.info(f"提取到-S参数内容: {s_content}")
                                
                                # 分割参数
                                if '.py' in s_content:
                                    # 分割脚本名和参数
                                    parts = s_content.split('.py', 1)
                                    if len(parts) > 1:
                                        # 提取.py后面的参数
                                        param_part = parts[1].strip()
                                        if param_part:
                                            logger.info(f"提取到的参数部分: {param_part}")
                                            # 直接用空格分割参数
                                            split_args = param_part.split()
                                            try:
                                                args = parser.parse_args(split_args)
                                                func_name = args.func
                                                logger.info(f"完整命令行参数解析结果: func={func_name}")
                                            except Exception as e:
                                                logger.error(f"完整命令行参数解析失败: {str(e)}")
                                                # 简单解析--func参数
                                                if '--func' in param_part:
                                                    func_start = param_part.find('--func') + len('--func')
                                                    func_name = param_part[func_start:].strip().split()[0] if func_start < len(param_part) else None
                                                    logger.info(f"简单参数解析结果: func={func_name}")
        except Exception as e:
            logger.error(f"获取完整命令行失败: {str(e)}")
        
        # 如果环境变量中没有函数名，尝试从命令行获取
        if not func_name:
            # 尝试标准解析
            try:
                args = parser.parse_args()
                func_name = args.func if args else None
                if func_name:
                    logger.info(f"从命令行参数获取函数名: {func_name}")
            except:
                pass
        
        # 最后检查：如果还是没有函数名
        if not func_name:
            logger.warning("未提供函数名：既没有环境变量 IDA_FUNC_NAME，也没有命令行参数")
        
        # 确定要分析的函数
        func_ea = None
        
        if func_name:
            func_ea = find_function_by_name(func_name)
            if func_ea is None:
                logger.error(f"未找到函数 '{func_name}'")
                # 列出前20个函数
                logger.info("可用函数列表（前20个）:")
                for i, f_ea in enumerate(list(idautils.Functions())[:20]):
                    logger.info(f"- {get_func_name(f_ea)} (0x{f_ea:x})")
                return
        else:
            # 使用光标位置
            try:
                cur = idc.here()
                if cur:
                    func_ea = idc.get_func_attr(cur, idc.FUNCATTR_START)
            except:
                pass
            
            if not func_ea:
                logger.error("请将光标放在目标函数中或通过--func参数指定函数名")
                return
        
        if not func_ea or func_ea == 0xffffffffffffffff:
            logger.error(f"无效的函数地址")
            return
        
        func_name = get_func_name(func_ea)
        logger.info(f"分析函数: {func_name} (0x{func_ea:x})")
        
        # 执行分析
        function_analysis = analyze_function(func_ea)
        data_flow_analysis = get_complete_data_flow(func_ea)
        
        # 合并结果
        combined_result = {
            "function": function_analysis["function"],
            "sinks": function_analysis["sinks"],
            "callers": function_analysis["callers"],
            "chains": function_analysis["chains"],
            "nl_assessments": function_analysis["nl_assessments"],
            "data_flow": {
                "forward_flow": data_flow_analysis["forward_flow"],
                "backward_flow": data_flow_analysis["backward_flow"],
                "callers": data_flow_analysis["callers"],
                "callees": data_flow_analysis["callees"]
            }
        }
        
        # 保存合并结果
        try:
            output_dir = get_output_dir()
            filename = os.path.join(output_dir, f"ida_combined_analysis_{func_name}_{func_ea:X}.json")
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(combined_result, f, indent=2, ensure_ascii=False)
            
            logger.info(f"合并分析结果已保存到: {filename}")
            
            # 输出摘要
            logger.info("="*50)
            logger.info(f"函数: {func_name}")
            logger.info(f"发现 {len(function_analysis['sinks'])} 个潜在风险点")
            for assessment in function_analysis["nl_assessments"]:
                logger.info(f"- {assessment['sink']}: {assessment['risk']} 风险")
            logger.info("="*50)
            
        except Exception as e:
            logger.error(f"保存失败: {str(e)}")
    
    except Exception as e:
        logger.error(f"分析过程出错: {str(e)}")
    finally:
        idc.qexit(0)

if __name__ == "__main__":
    main()
