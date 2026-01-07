# -*- coding: utf-8 -*-
#
# 功能：
#   - 自动分析二进制
#   - 导出所有有效函数的 Hex-Rays 伪代码到单个 C 文件
#   - 注释头格式与旧版 split_functions() 完全兼容
#   - 记录详细日志
#   - 清理 IDA 临时文件
#   - CLI / GUI 均可运行
#
# 使用：
#   idat.exe -A -T -S"export_all_funcs_cli.py" <binary>

import ida_auto
import ida_hexrays
import ida_kernwin
import ida_loader
import ida_funcs
import ida_lines
import ida_name
import ida_idaapi
import idaapi
import idautils
import ida_pro
import idc
import ida_nalt
import time
import os
import sys

# =========================
# 路径与输出文件（与 export_hexrays.py 对齐）
# =========================

bin_path = ida_nalt.get_input_file_path()
bin_name = os.path.basename(bin_path)
dir_path = os.path.dirname(bin_path)

output_path = os.path.join(dir_path, bin_name + "_pseudo.c")
log_path    = os.path.join(dir_path, bin_name + "_log.txt")

os.makedirs(dir_path, exist_ok=True)

# =========================
# 日志函数
# =========================

def log(msg):
    print(msg)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

# 初始化日志
with open(log_path, "w", encoding="utf-8") as f:
    f.write("=== export_all_funcs_cli.py start ===\n")

log(f"[+] Binary     : {bin_path}")
log(f"[+] Output C   : {output_path}")
log(f"[+] Log file   : {log_path}")

# =========================
# 等待自动分析
# =========================

log("[*] Waiting for auto-analysis...")
ida_auto.auto_wait()
log("[+] Auto-analysis finished")

# =========================
# 初始化 Hex-Rays
# =========================

log("[*] Initializing Hex-Rays...")
if not ida_hexrays.init_hexrays_plugin():
    log("[!] Hex-Rays unavailable")
    ida_pro.qexit(1)

# 稳定 Hex-Rays
log("[*] Stabilizing Hex-Rays...")
for i in range(3):
    ida_kernwin.process_ui_action("Empty", 0)
    ida_auto.auto_wait()
    time.sleep(0.5)
    log(f"    [+] refinement round {i+1}/3")

# =========================
# 过滤垃圾函数
# =========================

def is_bad_function(func):
    if func.flags & (ida_funcs.FUNC_THUNK | ida_funcs.FUNC_LIB):
        return True

    name = ida_funcs.get_func_name(func.start_ea)
    if name.startswith((
        "__imp_", "_imp_", "j_", "nullsub_", "__stub_", "__plt_"
    )):
        return True

    return False

# =========================
# 枚举函数
# =========================

log("[*] Collecting functions...")
funcs = []

for ea in idautils.Functions():
    f = ida_funcs.get_func(ea)
    if not f:
        continue
    if is_bad_function(f):
        continue
    funcs.append(f)

funcs.sort(key=lambda f: f.start_ea)
log(f"[+] {len(funcs)} valid functions found")

# =========================
# 导出伪代码（兼容旧 split）
# =========================

log("[*] Exporting pseudocode...")

exported = 0

with open(output_path, "w", encoding="utf-8") as out:
    for idx, func in enumerate(funcs, 1):
        name = ida_funcs.get_func_name(func.start_ea)
        ea   = func.start_ea

        log(f"[{idx}/{len(funcs)}] Decompile {name} @ 0x{ea:X}")

        try:
            cfunc = ida_hexrays.decompile(ea)
            if not cfunc:
                out.write(
                    "/**********************************************************************\n"
                    f" * 函数: {name} (地址: 0x{ea:X})\n"
                    " **********************************************************************/\n"
                    f"/* FAILED TO DECOMPILE {name} */\n\n"
                )
                continue

            # === 关键：旧 split_functions 兼容头 ===
            out.write(
                "/**********************************************************************\n"
                f" * 函数: {name} (地址: 0x{ea:X})\n"
                " **********************************************************************/\n"
            )

            for sl in cfunc.get_pseudocode():
                out.write(ida_lines.tag_remove(sl.line) + "\n")

            out.write("\n\n")
            exported += 1

        except Exception as e:
            out.write(
                "/**********************************************************************\n"
                f" * 函数: {name} (地址: 0x{ea:X})\n"
                " **********************************************************************/\n"
                f"/* ERROR: {e} */\n\n"
            )
            log(f"[!] Error decompiling {name}: {e}")

log(f"[+] Export finished: {exported}/{len(funcs)} functions")

# =========================
# 清理 IDA 临时文件（与 export_hexrays.py 一致）
# =========================

log("[*] Cleaning IDA temp files...")

TEMP_SUFFIXES = [".id0", ".id1", ".id2", ".idb", ".nam", ".til"]
for suffix in TEMP_SUFFIXES:
    tmp = bin_path + suffix
    if os.path.exists(tmp):
        try:
            os.remove(tmp)
            log(f"[+] Removed {tmp}")
        except Exception as e:
            log(f"[!] Failed to remove {tmp}: {e}")

# =========================
# 保存数据库并退出
# =========================

log("[*] Saving database...")
ida_loader.save_database(None, ida_loader.DBFL_COMP)

log("[+] Done, exiting IDA")
ida_pro.qexit(0)
