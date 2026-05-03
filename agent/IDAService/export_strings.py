"""
IDA 批量导出字符串脚本

使用方式：在 IDA 无界面模式下执行本脚本，生成当前二进制的字符串清单
输出位置与输入二进制同目录，文件名形如 <binary>_strings.json
"""

import json
import os
import string

import idaapi
import ida_bytes
import ida_idaapi
import ida_nalt
import ida_segment
import idautils
import idc


MIN_LEN = 4            # 最短字符串长度
MAX_LEN = 512          # 避免异常超长字符串

# 全局日志文件路径
LOG_PATH = ""

def log_message(msg: str):
    """记录日志到文件和控制台"""
    try:
        print(msg)
        if LOG_PATH:
            with open(LOG_PATH, 'a', encoding='utf-8') as f:
                f.write(msg + "\n")
    except:
        pass


def _is_printable(text: str) -> bool:
    printable = set(string.printable)
    return all(ch in printable for ch in text)


def _decode_string(ea: int, length: int, strtype: int) -> str | None:
    try:
        raw = ida_bytes.get_strlit_contents(ea, length, strtype)
        if raw is None:
            return None
        if isinstance(raw, bytes):
            try:
                return raw.decode("utf-8", errors="ignore")
            except Exception:
                return raw.decode("latin-1", errors="ignore")
        return str(raw)
    except Exception:
        return None


def collect_and_export_strings(output_path: str, bin_name: str):
    """流式收集并写入字符串，避免大文件 OOM"""
    log_message(f"[{bin_name}] 开始初始化字符串列表...")
    
    # 对于大文件，auto_wait 可能会导致无限期卡死，尝试移除
    # idaapi.auto_wait()

    str_list = idautils.Strings()

    # IDA 需要传入 list，而不是单个值；同时兼容 UTF-16 文本
    strtypes = []
    if hasattr(ida_nalt, "STRTYPE_C"):
        strtypes.append(ida_nalt.STRTYPE_C)
    if hasattr(ida_nalt, "STRTYPE_C_16"):
        strtypes.append(ida_nalt.STRTYPE_C_16)
    if not strtypes:  # 保底避免空列表
        strtypes = [0]

    str_list.setup(strtypes=strtypes)
    
    # 尝试获取总数（可能会慢，但有助于判断是否卡死）
    try:
        total_count = len(str_list)
        log_message(f"[{bin_name}] 字符串列表初始化完成，检测到约 {total_count} 条候选项")
    except Exception:
        log_message(f"[{bin_name}] 字符串列表初始化完成，无法获取总数")
        total_count = -1

    # 手动构建 JSON，流式写入
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write('{\n')
            f.write(f'  "binary": "{bin_name}",\n')
            f.write('  "strings": [\n')
            
            valid_count = 0
            processed_count = 0
            
            for item in str_list:
                processed_count += 1
                if processed_count % 50000 == 0:
                    log_message(f"[{bin_name}] 已扫描 {processed_count} 条，已导出 {valid_count} 条...")

                try:
                    text = _decode_string(int(item.ea), int(item.length), int(item.strtype))
                    if not text:
                        continue
                    text = text.strip("\x00\r\n\t ")
                    if len(text) < MIN_LEN or len(text) > MAX_LEN:
                        continue
                    if not _is_printable(text):
                        continue

                    # 修正：get_segm_name 需要 segment_t 对象而不是地址
                    seg = ida_segment.getseg(item.ea)
                    seg_name = ida_segment.get_segm_name(seg) if seg else ""
                    
                    obj = {
                        "address": hex(int(item.ea)),
                        "length": len(text),
                        "string_type": int(item.strtype),
                        "section": seg_name,
                        "value": text
                    }
                    
                    if valid_count > 0:
                        f.write(',\n')
                    f.write(json.dumps(obj, ensure_ascii=False))
                    valid_count += 1
                    
                except Exception:
                    continue

            f.write('\n  ],\n')
            f.write(f'  "count": {valid_count}\n')
            f.write('}\n')
            log_message(f"[{bin_name}] 导出完成，共有效字符串 {valid_count} 条")
            
    except Exception as e:
        log_message(f"[{bin_name}] 导出过程中发生错误: {e}")
        # 尝试写入一个合法的结尾，以便 JSON 仍可解析（部分数据）
        try:
            with open(output_path, "a", encoding="utf-8") as f:
                f.write('\n  ],\n')
                f.write(f'  "count": {valid_count},\n')
                f.write(f'  "error": "{str(e)}"\n')
                f.write('}\n')
        except:
            pass


def main():
    global LOG_PATH
    
    # 获取原始二进制文件名（用于命名输出文件）
    bin_path = ida_nalt.get_input_file_path()
    bin_name = os.path.basename(bin_path)
    
    # 获取当前 IDA 数据库文件路径（.i64/.idb）
    # 这样即使原始二进制被移动，也能正确获取输出目录
    idb_path = idc.get_idb_path()
    dir_path = os.path.dirname(idb_path)
    
    # 如果 idb_path 为空（极少情况），回退到原始路径
    if not dir_path or not os.path.exists(dir_path):
        dir_path = os.path.dirname(bin_path)
        # 如果原始路径也不存在，使用当前工作目录
        if not os.path.exists(dir_path):
            dir_path = os.getcwd()
    
    # 初始化日志文件
    LOG_PATH = os.path.join(dir_path, f"{bin_name}_strings_log.txt")
    # 清空旧日志
    with open(LOG_PATH, 'w', encoding='utf-8') as f:
        f.write(f"开始导出字符串: {bin_name}\n")
        f.write(f"IDB路径: {idb_path}\n")
        f.write(f"输出目录: {dir_path}\n")

    # 输出路径
    output_path = os.path.join(dir_path, f"{bin_name}_strings.json")
    
    collect_and_export_strings(output_path, bin_name)

    idc.qexit(0)


if __name__ == "__main__":
    main()
