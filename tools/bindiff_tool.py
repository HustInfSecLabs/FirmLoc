# VulnAgent/tools/bindiff_tool.py

import os
import shutil

import subprocess
from config import config_manager


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

    bindiff_bin = (
        config_manager.config.get("BINARY_TOOLS", "bindiff_path", fallback="")
        or os.environ.get("BINDIFF_PATH")
        or shutil.which("bindiff")
        or "bindiff"
    )

    # -- ① 默认格式
    cmd1 = [bindiff_bin, primary_export, secondary_export, "--output_dir", output_dir]
    # -- ② 追加 log 格式
    cmd2 = [bindiff_bin, primary_export, secondary_export, "--output_format", "log", "--output_dir", output_dir]

    try:
        result1 = subprocess.run(cmd1, capture_output=True, text=True, check=True)
        result2 = subprocess.run(cmd2, capture_output=True, text=True, check=True)
        return {
            "success": True,
            "output_dir": output_dir,
            "stdout": result1.stdout,
            "stderr": result1.stderr,
            "stdout_log": result2.stdout,
            "stderr_log": result2.stderr,
            "bindiff_bin": bindiff_bin
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "bindiff 可执行程序不存在，请在 config.ini 的 [BINARY_TOOLS] 中设置 bindiff_path",
            "bindiff_bin": bindiff_bin,
            "path": os.environ.get("PATH", "")
        }
    except subprocess.CalledProcessError as e:
        return {
            "success": False,
            "error": "bindiff 执行失败",
            "stderr": e.stderr,
            "bindiff_bin": bindiff_bin
        }
