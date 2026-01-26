# -*- coding: utf-8 -*-
"""
IDA 脚本：获取函数的交叉引用信息

功能：
    - 获取指定函数的调用者 (callers / xrefs to)
    - 获取指定函数调用的函数 (callees / xrefs from)
    - 支持递归获取调用链

使用：
    通过 app.py 的 /get_function_xrefs 端点调用
    参数通过环境变量传递：
        XREF_FUNCTION_NAME: 目标函数名
        XREF_TYPE: "caller" 或 "callee"
        XREF_DEPTH: 递归深度 (默认 1)
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
from collections import deque


def get_func_name(ea):
    """获取函数名"""
    name = ida_funcs.get_func_name(ea)
    if not name:
        name = ida_name.get_ea_name(ea)
    if not name:
        name = f"sub_{ea:X}"
    return name


def find_function_by_name(target_name):
    """通过名称查找函数地址"""
    for ea in idautils.Functions():
        name = get_func_name(ea)
        if name == target_name:
            return ea
    return None


def get_callers(func_ea, max_depth=1):
    """
    获取调用指定函数的所有函数 (向上追溯调用者)
    
    返回格式:
    {
        "function_name": {
            "address": "0x...",
            "callers": [
                {
                    "name": "caller_func",
                    "address": "0x...",
                    "call_site": "0x...",  # 调用发生的地址
                    "call_context": "..."   # 调用处的代码片段
                }
            ]
        }
    }
    """
    result = {}
    visited = set()
    queue = deque([(func_ea, 0)])  # (地址, 当前深度)
    
    while queue:
        current_ea, depth = queue.popleft()
        
        if current_ea in visited or depth > max_depth:
            continue
        visited.add(current_ea)
        
        func_name = get_func_name(current_ea)
        callers = []
        
        # 获取所有引用到这个函数的位置
        for xref in idautils.XrefsTo(current_ea):
            # 检查引用来源是否在某个函数内
            caller_func = ida_funcs.get_func(xref.frm)
            if not caller_func:
                continue
            
            caller_ea = caller_func.start_ea
            caller_name = get_func_name(caller_ea)
            
            # 获取调用处的代码上下文
            call_context = ""
            try:
                disasm = idc.generate_disasm_line(xref.frm, 0)
                if disasm:
                    call_context = disasm
            except:
                pass
            
            callers.append({
                "name": caller_name,
                "address": f"0x{caller_ea:X}",
                "call_site": f"0x{xref.frm:X}",
                "call_context": call_context
            })
            
            # 如果还没达到最大深度，将调用者加入队列
            if depth < max_depth and caller_ea not in visited:
                queue.append((caller_ea, depth + 1))
        
        result[func_name] = {
            "address": f"0x{current_ea:X}",
            "depth": depth,
            "callers": callers
        }
    
    return result


def get_callees(func_ea, max_depth=1):
    """
    获取指定函数调用的所有函数 (向下追溯被调用者)
    
    返回格式:
    {
        "function_name": {
            "address": "0x...",
            "callees": [
                {
                    "name": "callee_func",
                    "address": "0x...",
                    "call_site": "0x..."
                }
            ]
        }
    }
    """
    result = {}
    visited = set()
    queue = deque([(func_ea, 0)])
    
    while queue:
        current_ea, depth = queue.popleft()
        
        if current_ea in visited or depth > max_depth:
            continue
        visited.add(current_ea)
        
        func = ida_funcs.get_func(current_ea)
        if not func:
            continue
        
        func_name = get_func_name(current_ea)
        callees = []
        
        # 遍历函数内的所有指令
        for head in idautils.Heads(func.start_ea, func.end_ea):
            for xref in idautils.XrefsFrom(head, 0):
                # 检查是否是调用类型
                if xref.type not in (idc.fl_CN, idc.fl_CF):
                    continue
                
                callee_func = ida_funcs.get_func(xref.to)
                if not callee_func:
                    # 可能是外部函数
                    callee_name = get_func_name(xref.to)
                    callee_ea = xref.to
                else:
                    callee_name = get_func_name(callee_func.start_ea)
                    callee_ea = callee_func.start_ea
                
                callees.append({
                    "name": callee_name,
                    "address": f"0x{callee_ea:X}",
                    "call_site": f"0x{head:X}"
                })
                
                # 如果还没达到最大深度，将被调用者加入队列
                if depth < max_depth and callee_func and callee_ea not in visited:
                    queue.append((callee_ea, depth + 1))
        
        result[func_name] = {
            "address": f"0x{current_ea:X}",
            "depth": depth,
            "callees": callees
        }
    
    return result


def main():
    """主函数"""
    print("=== get_function_xrefs.py start ===")
    
    # 等待自动分析
    ida_auto.auto_wait()
    
    # 从环境变量获取参数
    func_name = os.environ.get("XREF_FUNCTION_NAME", "")
    xref_type = os.environ.get("XREF_TYPE", "caller")  # "caller" or "callee"
    max_depth = int(os.environ.get("XREF_DEPTH", "1"))
    
    if not func_name:
        print("Error: XREF_FUNCTION_NAME not set")
        return {"error": "XREF_FUNCTION_NAME not set"}
    
    # 查找函数
    func_ea = find_function_by_name(func_name)
    if func_ea is None:
        print(f"Error: Function '{func_name}' not found")
        return {"error": f"Function '{func_name}' not found"}
    
    print(f"Found function: {func_name} at 0x{func_ea:X}")
    print(f"Xref type: {xref_type}, max depth: {max_depth}")
    
    # 获取交叉引用
    if xref_type == "callee":
        result = get_callees(func_ea, max_depth)
    else:
        result = get_callers(func_ea, max_depth)
    
    # 输出结果
    bin_path = ida_nalt.get_input_file_path()
    output_path = os.path.join(
        os.path.dirname(bin_path),
        f"{os.path.basename(bin_path)}_{func_name}_xrefs.json"
    )
    
    output = {
        "binary": os.path.basename(bin_path),
        "target_function": func_name,
        "xref_type": xref_type,
        "max_depth": max_depth,
        "timestamp": datetime.now().isoformat(),
        "result": result
    }
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    print(f"Results saved to: {output_path}")
    print("=== get_function_xrefs.py done ===")
    
    return output


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        ida_pro.qexit(0)
