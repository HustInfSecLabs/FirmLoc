### export_all_funcs_cli.py
# -*- coding: utf-8 -*-
# 导出所有函数的伪代码到单个文件，可在CLI或GUI下运行
# 使用方法: idat.exe -A -T -S"export_all_funcs_cli.py <output_dir>" <binary_file>

import ida_auto
import ida_hexrays
import ida_kernwin
import ida_loader
import ida_funcs
import ida_lines
import ida_name
import ida_idaapi
import idautils
import ida_pro
import idc
import sys
import time
import os

# 参数
argv = idc.ARGV
if len(argv) >= 2:
    export_dir = os.path.abspath(argv[1])
else:
    # default: next to idb
    idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)
    export_dir = os.path.join(os.path.dirname(idb_path), "export")
os.makedirs(export_dir, exist_ok=True)
out_file = os.path.join(export_dir, "all_functions.c")
print(f"[+] Output file: {out_file}")

# 工具函数
def is_bad_function(func):
    """
    过滤 thunk / library / 外部垃圾函数
    """
    if func.flags & (ida_funcs.FUNC_THUNK | ida_funcs.FUNC_LIB):
        return True

    name = ida_funcs.get_func_name(func.start_ea)
    if name.startswith((
        "__imp_", "_imp_", "j_", "nullsub_", "__stub_", "__plt_"
    )):
        return True

    return False

def get_full_pseudocode(func):
    """
    安全获取完整伪代码
    """
    cfunc = ida_hexrays.decompile(func.start_ea)
    if not cfunc:
        return None
    return [ida_lines.tag_remove(sl.line) for sl in cfunc.get_pseudocode()]


# 等待分析完成
print("[*] Waiting for auto-analysis...")
ida_auto.auto_wait()
print("[+] Auto-analysis finished")

print("[*] Initializing Hex-Rays...")
if not ida_hexrays.init_hexrays_plugin():
    print("[!] Hex-Rays unavailable")
    ida_pro.qexit(1)

# 强制 Hex-Rays 稳定
print("[*] Forcing Hex-Rays refinement cycles...")
for i in range(5):
    ida_kernwin.process_ui_action("Empty", 0)
    ida_auto.auto_wait()
    time.sleep(1)
    print(f"    [+] refinement round {i+1}/5")

# 枚举 + 过滤函数
print("[*] Collecting functions...")
good_funcs = []
for f_ea in idautils.Functions():
    func = ida_funcs.get_func(f_ea)
    if not func:
        continue
    if is_bad_function(func):
        continue
    good_funcs.append(func)

print(f"[+] {len(good_funcs)} valid functions found")

# 稳定反编译顺序
good_funcs.sort(key=lambda f: f.start_ea)

# 导出伪代码
print("[*] Exporting pseudocode...")
with open(out_file, "w", encoding="utf-8") as f:
    for idx, func in enumerate(good_funcs, 1):
        name = ida_funcs.get_func_name(func.start_ea)
        print(f"[{idx}/{len(good_funcs)}] {name}")

        try:
            pseudo = get_full_pseudocode(func)
            if not pseudo:
                f.write(f"\n/* FAILED TO DECOMPILE {name} */\n")
                continue

            f.write("\n/*=============================== */\n")
            f.write(f"/* {name} @ 0x{func.start_ea:X} */\n")
            f.write("\n".join(pseudo))
            f.write("\n\n")

        except Exception as e:
            f.write(f"\n/* ERROR {name}: {e} */\n")

print("[+] Export finished")

# 保存数据库并退出
print("[*] Saving database...")
ida_loader.save_database(None, ida_loader.DBFL_COMP)
print("[+] Done, exiting IDA")
ida_pro.qexit(0)
