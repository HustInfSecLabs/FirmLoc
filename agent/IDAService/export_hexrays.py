# export_hexrays.py
import idaapi
import idautils
import ida_hexrays
import idc
import os
import ida_nalt

bin_path = ida_nalt.get_input_file_path()
bin_name = os.path.basename(bin_path)
dir_path = os.path.dirname(bin_path)

output_path = os.path.join(dir_path, bin_name + '_pseudo.c')
log_path = os.path.join(dir_path, bin_name + '_log.txt')

# 确保输出目录存在
os.makedirs(dir_path, exist_ok=True)

def log_message(msg):
    """辅助函数：记录日志消息"""
    with open(log_path, 'a', encoding='utf-8') as log_file:
        log_file.write(msg + "\n")

# 清空或创建日志文件
with open(log_path, 'w', encoding='utf-8') as log_file:
    log_file.write("开始导出伪代码...\n")

idaapi.auto_wait()  # 等待自动分析完成

# 检查Hex-Rays插件是否可用
if not idaapi.init_hexrays_plugin():
    log_message("错误: Hex-Rays反编译器插件不可用")
    idc.qexit(1)
    raise RuntimeError("Hex-Rays反编译器插件不可用")

def export_pseudo_code(output_file):
    """导出当前二进制文件的伪C代码到指定文件"""
    try:
        funcs = list(idautils.Functions())
        total_funcs = len(funcs)
        exported_count = 0
        
        with open(output_file, 'w', encoding='utf-8') as output_f:
            for i, func_ea in enumerate(funcs):
                func_name = idaapi.get_func_name(func_ea)
                log_message(f"处理函数 {i+1}/{total_funcs}: {func_name} @ {hex(func_ea)}")
                
                # 获取函数对象
                func = idaapi.get_func(func_ea)
                if not func:
                    log_message(f"警告: 无法获取函数对象 @ {hex(func_ea)}")
                    continue
                    
                # 尝试反编译函数
                try:
                    cfunc = idaapi.decompile(func_ea)
                    if not cfunc:
                        log_message(f"警告: 无法反编译函数 {func_name} @ {hex(func_ea)}")
                        continue
                        
                    # 获取伪代码
                    pseudo_code = str(cfunc)
                    
                    # 写入文件
                    output_f.write(f"/{'*' * 70}\n")
                    output_f.write(f" * 函数: {func_name} (地址: {hex(func_ea)})\n")
                    output_f.write(f" {'*' * 70}/\n\n")
                    output_f.write(pseudo_code)
                    output_f.write("\n\n\n")
                    exported_count += 1
                    
                except Exception as e:
                    log_message(f"反编译错误 {func_name} @ {hex(func_ea)}: {str(e)}")
        
        log_message(f"\n导出完成: {exported_count}/{total_funcs} 个函数已导出到 {output_file}")
        return True
        
    except Exception as e:
        log_message(f"导出过程中发生严重错误: {str(e)}")
        return False

# 执行导出
export_pseudo_code(output_path)

# 清理临时文件
TEMP_SUFFIXES = [".id0", ".id1", ".id2", ".idb", ".nam", ".til"]
for suffix in TEMP_SUFFIXES:
    temp_file = bin_path + suffix
    if os.path.exists(temp_file):
        try:
            os.remove(temp_file)
            log_message(f"已删除临时文件: {temp_file}")
        except Exception as e:
            log_message(f"删除临时文件失败 {temp_file}: {str(e)}")

idc.qexit(0)  # 自动退出IDA
