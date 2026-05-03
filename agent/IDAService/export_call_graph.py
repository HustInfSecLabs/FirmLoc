# -*- coding: utf-8 -*-
"""
IDA 脚本：导出函数调用图 (Call Graph)

功能：
    - 导出整个二进制的函数调用图
    - 输出为 JSON 格式，包含节点(函数)和边(调用关系)

使用：
    idat.exe -A -T -S"export_call_graph.py" <binary>
"""

import ida_auto
import ida_funcs
import ida_name
import ida_nalt
import ida_pro
import idautils
import idc
import json
import os
from datetime import datetime


def setup_logger():
    """设置简单的日志记录"""
    bin_path = ida_nalt.get_input_file_path()
    dir_path = os.path.dirname(bin_path)
    log_path = os.path.join(dir_path, f"{os.path.basename(bin_path)}_call_graph_log.txt")
    
    def log(msg):
        print(msg)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().strftime('%H:%M:%S')} - {msg}\n")
    
    return log


def get_func_name(ea):
    """获取函数名"""
    name = ida_funcs.get_func_name(ea)
    if not name:
        name = ida_name.get_ea_name(ea)
    if not name:
        name = f"sub_{ea:X}"
    return name


def is_valid_function(func):
    """过滤无效函数"""
    if func.flags & (ida_funcs.FUNC_THUNK | ida_funcs.FUNC_LIB):
        return False
    
    name = get_func_name(func.start_ea)
    if name.startswith(("__imp_", "_imp_", "j_", "nullsub_", "__stub_", "__plt_")):
        return False
    
    return True


def export_call_graph():
    """导出调用图"""
    log = setup_logger()
    log("=== export_call_graph.py start ===")
    
    # 等待自动分析
    log("Waiting for auto-analysis...")
    ida_auto.auto_wait()
    log("Auto-analysis finished")
    
    bin_path = ida_nalt.get_input_file_path()
    bin_name = os.path.basename(bin_path)
    dir_path = os.path.dirname(bin_path)
    
    # 收集所有有效函数
    log("Collecting functions...")
    functions = {}
    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        if not func or not is_valid_function(func):
            continue
        
        name = get_func_name(ea)
        functions[ea] = {
            "name": name,
            "address": f"0x{ea:X}",
            "start": ea,
            "end": func.end_ea,
            "size": func.end_ea - ea
        }
    
    log(f"Found {len(functions)} valid functions")
    
    # 构建调用图
    log("Building call graph...")
    nodes = []
    edges = []
    
    for ea, func_info in functions.items():
        # 添加节点
        nodes.append({
            "id": func_info["name"],
            "address": func_info["address"],
            "size": func_info["size"]
        })
        
        # 遍历函数内的所有调用
        func = ida_funcs.get_func(ea)
        if not func:
            continue
        
        # 获取被调用的函数
        callees = set()
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for xref in idautils.XrefsFrom(head, 0):
                # 检查是否是调用类型的引用
                if xref.type in (idc.fl_CN, idc.fl_CF):  # 近调用/远调用
                    callee_func = ida_funcs.get_func(xref.to)
                    if callee_func and callee_func.start_ea in functions:
                        callee_name = functions[callee_func.start_ea]["name"]
                        callees.add(callee_name)
        
        # 添加边
        for callee in callees:
            edges.append({
                "from": func_info["name"],
                "to": callee
            })
    
    log(f"Built call graph: {len(nodes)} nodes, {len(edges)} edges")
    
    # 输出结果
    result = {
        "binary": bin_name,
        "timestamp": datetime.now().isoformat(),
        "nodes": nodes,
        "edges": edges,
        "statistics": {
            "total_functions": len(nodes),
            "total_calls": len(edges)
        }
    }
    
    output_path = os.path.join(dir_path, f"{bin_name}_call_graph.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    
    log(f"Call graph exported to: {output_path}")
    log("=== export_call_graph.py done ===")
    
    return result


if __name__ == "__main__":
    try:
        export_call_graph()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        ida_pro.qexit(0)
