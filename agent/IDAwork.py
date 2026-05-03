import subprocess
import os
import shutil

# ============================================
# 配置区
# ============================================

IDA_PATH = r"D:/IDA_Pro_v7.5_Portable/idat.exe"   # idat.exe路径
TEMP_SUFFIXES = [".id0", ".id1", ".id2", ".idb", ".nam", ".til"]  # IDA临时文件后缀

# ============================================
# 主函数
# ============================================

def export_and_extract(work_dir, output_dir=None):
    """
    从工作目录批量导出伪C代码并提取CFG信息。
    
    参数:
        work_dir: 要处理的二进制文件所在目录
        output_dir: 结果保存目录，默认是 work_dir/output

    返回:
        List of (binary name, c file full path)
    """
    if output_dir is None:
        output_dir = os.path.join(work_dir, "output")

    # 确保输出目录存在
    os.makedirs(output_dir, exist_ok=True)

    # 切换到工作目录
    os.chdir(work_dir)

    print("\n==== 开始处理所有文件 ====\n")

    result_c_files = []  # 用来存储每个二进制对应生成的 .c 文件路径

    for file in os.listdir(work_dir):
        ext = os.path.splitext(file)[1].lower()
        filename = os.path.splitext(file)[0]

        # 跳过bat、py、txt、目录
        if ext in [".bat", ".py", ".txt", ".md", ".log"] or not os.path.isfile(file):
            continue

        print("\n===========================================")
        print(f"正在处理文件: {file}")
        print("===========================================")

        # 为每个文件创建子目录
        file_output_dir = os.path.join(output_dir, filename)
        os.makedirs(file_output_dir, exist_ok=True)

        export_log = os.path.join(file_output_dir, "export_log.txt")

        # 步骤1：导出Hexrays伪代码
        print("[1/2] 导出伪代码中...")
        try:
            subprocess.run([
                IDA_PATH,
                f'-Ohexrays:{filename}:ALL',
                '-A',
                file
            ], stdout=open(export_log, 'w', encoding='utf-8'), stderr=subprocess.STDOUT, check=True)
        except subprocess.CalledProcessError as e:
            print(f"导出伪代码失败: {e}")

        # 步骤2：运行BinaryInfoExtractor.py提取函数CFG信息
        print("[2/2] 提取函数CFG信息中...")
        try:
            subprocess.run([
                IDA_PATH,
                '-A',
                f'-SBinaryInfoExtractor.py',
                file
            ], stdout=open(export_log, 'a', encoding='utf-8'), stderr=subprocess.STDOUT, check=True)
        except subprocess.CalledProcessError as e:
            print(f"提取CFG信息失败: {e}")

        # 移动生成的 .c 和 .info 文件
        c_file = f"{filename}.c"
        info_file = f"{filename}.info"

        c_file_path = os.path.join(file_output_dir, c_file)
        info_file_path = os.path.join(file_output_dir, info_file)

        if os.path.exists(c_file):
            shutil.move(c_file, c_file_path)
            result_c_files.append((filename, c_file_path))  # 保存成功导出的伪C路径
            print(f"导出: {c_file_path}")
        else:
            print(f"没有生成 {c_file} 文件")

        if os.path.exists(info_file):
            shutil.move(info_file, info_file_path)

        print(f"完成处理: {file}")

    # 清理IDA中间临时文件
    print("\n==== 清理IDA中间文件 ====\n")
    for suffix in TEMP_SUFFIXES:
        for file in os.listdir(work_dir):
            if file.endswith(suffix):
                try:
                    os.remove(file)
                    print(f"已删除: {file}")
                except Exception as e:
                    print(f"删除 {file} 失败: {e}")

    print("\n==== 全部处理完毕 ====\n")

    return result_c_files  # 返回列表

# ============================================
# 支持单独运行
# ============================================

if __name__ == "__main__":
    c_files = export_and_extract(work_dir=r"D:/HUSTCourse/402/chenyi_zhu/TestCase/firmware")
    print("\n==== 导出的伪C文件列表 ====")
    for name, path in c_files:
        print(f"{name}: {path}")
