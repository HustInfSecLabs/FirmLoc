# VulnAgent/tools/bindiff_tool.py

import subprocess
import os

def run_bindiff(primary_export: str, secondary_export: str, output_dir: str) -> dict:
    """
    执行 bindiff 工具对比两个 BinExport 文件，输出到指定目录。
    返回结构化执行结果。
    """
    if not os.path.exists(primary_export) or not os.path.exists(secondary_export):
        return {
            "success": False,
            "error": "输入文件不存在",
            "primary": primary_export,
            "secondary": secondary_export
        }

    os.makedirs(output_dir, exist_ok=True)

    cmd = ["bindiff", primary_export, secondary_export, "--output_dir", output_dir]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return {
            "success": True,
            "output_dir": output_dir,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except subprocess.CalledProcessError as e:
        return {
            "success": False,
            "error": "bindiff 执行失败",
            "stderr": e.stderr
        }
