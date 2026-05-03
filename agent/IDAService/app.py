from flask import Flask, request, send_file, abort, jsonify
import tempfile
import os, sys, zipfile
import subprocess
import shutil
import logging
import configparser
from datetime import datetime
import time
import psutil, json

# Flask服务端口
port = 5000

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_CONFIG_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "..", "config", "config.ini"))


def _load_binary_tool_paths() -> dict:
    parser = configparser.ConfigParser()
    parser.read(PROJECT_CONFIG_PATH, encoding="utf-8")
    section = "BINARY_TOOLS"
    return {
        "ida32_path": parser.get(section, "ida32_path", fallback="/home/ubuntu-24-04-4/linux_ida/ida"),
        "ida64_path": parser.get(section, "ida64_path", fallback="/home/ubuntu-24-04-4/linux_ida/ida"),
        "idat32_path": parser.get(section, "idat32_path", fallback="/home/ubuntu-24-04-4/linux_ida/idat"),
        "idat64_path": parser.get(section, "idat64_path", fallback="/home/ubuntu-24-04-4/linux_ida/idat"),
    }


_BINARY_TOOL_PATHS = _load_binary_tool_paths()

# 环境变量配置（Linux 优先）
PYTHONHOME = os.environ.get("IDA_PYTHONHOME", "")
PYTHONPATH = os.environ.get("IDA_PYTHONPATH", "")
IDA32_PATH = _BINARY_TOOL_PATHS["ida32_path"]
IDA64_PATH = _BINARY_TOOL_PATHS["ida64_path"]
IDAT32_PATH = _BINARY_TOOL_PATHS["idat32_path"]
IDAT64_PATH = _BINARY_TOOL_PATHS["idat64_path"]

# 配置分析脚本路径, 确保绝对路径
BINEXPORT_SCRIPT = os.path.join(BASE_DIR, "export_binexport.py")
EXPORT_SCRIPT = os.path.join(BASE_DIR, "export_hexrays.py")
EXPORT_STRINGS_SCRIPT = os.path.join(BASE_DIR, "export_strings.py")
ANALYZE_SCRIPT = os.path.join(BASE_DIR, "analyze.py")
WAIT_SCRIPT = os.path.join(BASE_DIR, "wait_for_analysis.py")
STRING_XREF_SCRIPT = os.path.join(BASE_DIR, "string_xref_analysis.py")

# 最大文件大小限制
MAX_FILE_SIZE = 1024 * 1024 * 1024 * 5  # 5GB
TIMEOUT = 3000  # 50分钟超时

# 导出伪C代码的等待检测时间
max_wait_time = 30  # 最大等待时间（秒）
check_interval = 0.5  # 检查间隔（秒）

def clear_ida_cache(bin_path):
    """
    删除与bin_path相关的IDA缓存文件（如 .id0/.id1/.idb/.nam/.til 等）
    支持扩展名为.so、.bin等的 ELF 文件。
    """
    patterns = [
        bin_path + '.id0',
        bin_path + '.id1',
        bin_path + '.id2',
        bin_path + '.nam',
        bin_path + '.til',
        bin_path + '.idb',
        bin_path + '.i64',

    ]
    for file_path in patterns:
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.info(f"[Cache Clean] Removed: {file_path}")
        except Exception as e:
            logger.warning(f"[Cache Clean] Failed to remove {file_path}: {str(e)}")

# 配置日志记录
def setup_logger():
    # 创建log目录
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "log")
    os.makedirs(log_dir, exist_ok=True)
    
    # 设置日志文件名
    log_file = os.path.join(log_dir, f"{datetime.now().strftime('%Y%m%d')}.log")
    
    # 配置日志格式和级别
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    return logging.getLogger(__name__)

# 初始化logger
logger = setup_logger()

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

logger.info(f"Analyze script path: {BINEXPORT_SCRIPT}")
logger.info(f"Export script path: {EXPORT_SCRIPT}")
logger.info(f"Analyze script path: {ANALYZE_SCRIPT}")

# 创建base输出目录：ida_output\{日期}
base_dir = os.path.dirname(os.path.abspath(__file__))
ida_output_dir = os.path.join(base_dir, "ida_output")
os.makedirs(ida_output_dir, exist_ok=True)
   
@app.route('/reversing_analyze_screenshot', methods=['POST'])
def analyze_with_screenshot():
    """无界面模式下不支持截图接口"""
    abort(410, "Screenshot endpoint is disabled in headless mode")


@app.route('/export_binexport', methods=['POST'])
def analyze():
    """根据文件名分析已存在的二进制文件"""
    try:
        # 获取请求参数
        binary_name = request.form.get('binary_name')
        binary_path = request.form.get('binary_path')
        if not binary_name and not binary_path:
            abort(400, "No binary name or binary path provided")

        # 获取IDA版本参数 (默认为ida32)
        ida_version = request.form.get('ida_version', 'ida').lower()
        if ida_version == 'ida64':
            print("Using IDA64")
            IDAT_PATH = IDAT64_PATH
        else:
            IDAT_PATH = IDAT32_PATH

        # 构建当天日期目录路径
        date_str = datetime.now().strftime('%Y%m%d')
        analysis_dir = os.path.join(ida_output_dir, date_str)

        # 优先使用直接传入的二进制绝对路径；否则回退到历史目录模式
        if binary_path:
            bin_path = os.path.abspath(binary_path)
            if not os.path.isfile(bin_path):
                abort(404, f"Binary file not found: {bin_path}")
        else:
            if not os.path.exists(analysis_dir):
                abort(404, f"Analysis directory not found: {analysis_dir}")
            bin_path = os.path.join(analysis_dir, binary_name)
            if not os.path.isfile(bin_path):
                abort(404, f"Binary file not found: {binary_name}")

        logger.info(f"Found target file: {bin_path}")

        # 运行IDA分析
        cmd = [
            IDAT_PATH,
            '-A',  # 自动模式
            '-T',  # 不显示界面
            f'-S{BINEXPORT_SCRIPT}',  # 执行脚本
            bin_path
        ]
        logger.info(f"Executing: {' '.join(cmd)}")

        try:
            '''
            result = subprocess.run(
                cmd,
                cwd=analysis_dir,  # 在工作目录执行
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=TIMEOUT,
                env=os.environ.copy()
            )'''
            result = subprocess.run(
                cmd,
                cwd=os.path.dirname(bin_path),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=3600
            )

            print("[DEBUG] CMD =", cmd)
            print("[DEBUG] returncode =", result.returncode)
            print("[DEBUG] stdout =", result.stdout)
            print("[DEBUG] stderr =", result.stderr)

            if result.returncode != 0:
                raise RuntimeError(
                    f"IDA subprocess failed.\n"
                    f"cmd={cmd}\n"
                    f"returncode={result.returncode}\n"
                    f"stdout={result.stdout}\n"
                    f"stderr={result.stderr}"
                )
        except subprocess.TimeoutExpired:
            abort(408, "Analysis timeout")

        # 检查执行结果
        if result.returncode != 0:
            error_msg = (result.stderr or "").strip()
            logger.error(f"IDA Error (code {result.returncode}): {error_msg}")
            abort(500, f"IDA analysis failed: {error_msg}")

        logger.info(f"Analysis completed successfully")
        # 获取生成文件（脚本生成同名 .BinExport，IDB/i64 可选）
        export_path = bin_path + '.BinExport'

        # 先保证 BinExport 一定存在
        if not os.path.exists(export_path) or os.path.getsize(export_path) == 0:
            logger.error(f"BinExport file missing or empty: {export_path}")
            abort(500, f"BinExport file not generated or empty: {export_path}")

        # 尝试同时兼容 .i64 / .idb，两者都没有也不报错，只 warning
        idb_candidates = [bin_path + '.i64', bin_path + '.idb']
        idb_path = None
        for cand in idb_candidates:
            if os.path.exists(cand) and os.path.getsize(cand) > 0:
                idb_path = cand
                break

        if idb_path:
            logger.info(f"Using IDB file: {idb_path}")
        else:
            logger.warning(f"IDB/i64 file not found for {bin_path}, continue without IDB")

        # 创建 zip 文件（BinExport 必须打包，IDB 有就顺便打进去）
        zip_base_dir = os.path.dirname(bin_path)
        zip_stem = os.path.basename(bin_path)
        zip_filename = os.path.join(zip_base_dir, f"ida_analysis_{zip_stem}.zip")
        with zipfile.ZipFile(zip_filename, 'w') as zipf:
            zipf.write(export_path, os.path.basename(export_path))
            if idb_path:
                zipf.write(idb_path, os.path.basename(idb_path))

        # 清理旧的IDA缓存文件
        clear_ida_cache(bin_path)

        # 返回zip文件
        return send_file(
            zip_filename,
            as_attachment=True,
            download_name=f"ida_analysis_{zip_stem}.zip",
            mimetype='application/zip'
        )


    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}", exc_info=True)
        abort(500, f"Analysis error: {str(e)}")


def convert_size(size_bytes):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} TB"


@app.route('/export_pseudo_c', methods=['POST'])
def export_pseudo_c():
    """根据文件名导出二进制文件的伪C代码"""
    try:
        # 获取请求参数
        binary_name = request.form.get('binary_name')
        binary_path = request.form.get('binary_path')
        if not binary_name and not binary_path:
            abort(400, "No binary name or binary path provided")

        # 获取IDA版本参数 (默认为ida32)
        ida_version = request.form.get('ida_version', 'ida').lower()
        if ida_version == 'ida64':
            logger.info("Using IDA64")
            IDAT_PATH = IDAT64_PATH
        else:
            IDAT_PATH = IDAT32_PATH

        # 构建当天日期目录路径
        date_str = datetime.now().strftime('%Y%m%d')
        analysis_dir = os.path.join(ida_output_dir, date_str)

        # 优先使用直接传入的二进制绝对路径；否则回退到历史目录模式
        if binary_path:
            bin_path = os.path.abspath(binary_path)
            if not os.path.isfile(bin_path):
                abort(404, f"Binary file not found: {bin_path}")
        else:
            source_output_dir = os.path.join(analysis_dir, "source")
            os.makedirs(source_output_dir, exist_ok=True)
            bin_path = os.path.join(analysis_dir, binary_name)
            if not os.path.isfile(bin_path):
                abort(404, f"Binary file not found: {binary_name}")

        logger.info(f"Found target file: {bin_path}")

        # 运行IDA分析
        cmd = [
            IDAT_PATH,
            '-A',  # 自动模式
            '-T',  # 不显示界面
            f'-S{EXPORT_SCRIPT}',
            bin_path
        ]
        logger.info(f"Executing: {' '.join(cmd)}")

        start_time = time.time()
        try:
            result = subprocess.run(
                cmd,
                cwd=os.path.dirname(bin_path),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=TIMEOUT,
                env=os.environ.copy()
            )
        except subprocess.TimeoutExpired:
            # abort(408, "Export pseudo C timeout")
            logger.warning("Export pseudo C timeout")

        end_time = time.time()

        stdout_text = (result.stdout or "").strip()
        stderr_text = (result.stderr or "").strip()
        logger.info(f"[PseudoC] stdout for {binary_name}:\n{stdout_text}")
        logger.info(f"[PseudoC] stderr for {binary_name}:\n{stderr_text}")

        if result.returncode != 0:
            logger.error(f"[PseudoC] IDA exited with code {result.returncode}")
            abort(500, f"Pseudo C export failed: {stderr_text or stdout_text or 'unknown error'}")


        # 再次检查输出文件
        output_dir = os.path.dirname(bin_path)
        output_basename = os.path.basename(bin_path)
        output_filepath = os.path.join(output_dir, f"{output_basename}_pseudo.c")
        if not os.path.exists(output_filepath) or os.path.getsize(output_filepath) == 0:
            logger.error(f"Pseudo C file not found or empty: {output_filepath}")
            abort(500, f"Pseudo C file not generated or empty: {output_filepath}")


        source_output_dir = os.path.join(output_dir, "source")
        os.makedirs(source_output_dir, exist_ok=True)
        pseudo_filepath = os.path.join(source_output_dir, f"{output_basename}_pseudo.c")
        if os.path.exists(pseudo_filepath):
            os.remove(pseudo_filepath)
        shutil.move(output_filepath, source_output_dir)


        logger.info(f"{output_basename} Exported pseudo C completed, size: {convert_size(os.path.getsize(bin_path))}")
        logger.info(f"Export time: {end_time - start_time:.2f} seconds")

        # 清理旧的IDA缓存文件
        clear_ida_cache(bin_path)

        # 返回生成的伪C代码文件
        return send_file(
            pseudo_filepath,
            as_attachment=True,
            download_name=os.path.basename(pseudo_filepath),
            mimetype='text/plain'
        )

    except Exception as e:
        logger.error(f"Error during pseudo C export: {str(e)}", exc_info=True)
        abort(500, f"Pseudo C export error: {str(e)}")
     

@app.route('/get_function_call_info', methods=['POST'])
def get_function_call_info():
    """获取特定函数的调用链信息"""
    try:
        # 获取请求参数
        binary_name = request.form.get('binary_name')
        function_name = request.form.get('function_name')
        
        if not binary_name or not function_name:
            abort(400, "Missing required parameters: binary_name or function_name")

        # 获取IDA版本参数 (默认为ida32)
        ida_version = request.form.get('ida_version', 'ida').lower()
        if ida_version == 'ida64':
            logger.info("Using IDA64 for function call info")
            ida_path = IDA64_PATH
        else:
            ida_path = IDA32_PATH

        # 构建当天日期目录路径
        date_str = datetime.now().strftime('%Y%m%d')
        analysis_dir = os.path.join(ida_output_dir, date_str)
        # 确保工作目录存在，避免 Windows 下 cwd 非法导致 [WinError 267]
        os.makedirs(analysis_dir, exist_ok=True)
        
        # 查找目标文件（支持绝对路径或位于 analysis_dir 的文件名）
        bin_path = os.path.join(analysis_dir, binary_name)
        if not os.path.exists(bin_path):
            abort(404, f"Binary file not found: {binary_name}")
            print("[DEBUG][get_function_call_info] binary_name=", binary_name)

        logger.info(f"Getting call info for function {function_name} in file {bin_path}")
        
        # 调用IDA运行analyze.py分析目标函数
        try:
            # 构建IDA命令
            # 注意：不在 -S 参数中传递 --func，而是通过环境变量 IDA_FUNC_NAME 传递
            # Windows下需要特别注意引号的处理
            cmd = [
                ida_path,
                '-A',  # 自动模式
                f'-S{ANALYZE_SCRIPT}',  # 注意：移除引号，因为subprocess.run会自动处理路径
                bin_path
            ]
            
            logger.info(f"Running IDA command: {' '.join(cmd)}")
            logger.info(f"Function name passed via IDA_FUNC_NAME environment variable: {function_name}")
            
            # 执行命令，通过环境变量传递函数名
            proc_env = os.environ.copy()
            proc_env["IDA_FUNC_NAME"] = function_name  # 通过环境变量传递函数名
            
            logger.debug(f"Environment variables: IDA_FUNC_NAME={function_name}")

            result = subprocess.run(
                cmd,
                cwd=analysis_dir,  # 在工作目录执行
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=TIMEOUT,
                env=proc_env,
            )
            
            stdout_text = (result.stdout or "").strip()
            stderr_text = (result.stderr or "").strip()

            if stdout_text:
                logger.info(f"IDA stdout: {stdout_text}")
            if stderr_text:
                logger.info(f"IDA stderr: {stderr_text}")

            # 检查执行结果
            if result.returncode != 0:
                error_msg = stderr_text or stdout_text or f"IDA exited with code {result.returncode}"
                logger.error(f"IDA Error (code {result.returncode}): {error_msg}")
                abort(500, f"IDA analysis failed: {error_msg}")
            
            # 读取生成的JSON结果文件
            # 查找分析结果文件
            json_files = []
            for filename in os.listdir(analysis_dir):
                if not filename.endswith('.json'):
                    continue
                if not (filename.startswith('ida_slice_') or filename.startswith('ida_combined_analysis_')):
                    continue
                if function_name in filename:
                    json_files.append(os.path.join(analysis_dir, filename))
            
            if not json_files:
                # Fallback: accept any slice/combined json if none specifically include the function name
                for filename in os.listdir(analysis_dir):
                    if not filename.endswith('.json'):
                        continue
                    if not (filename.startswith('ida_slice_') or filename.startswith('ida_combined_analysis_')):
                        continue
                    json_files.append(os.path.join(analysis_dir, filename))

            if not json_files:
                # Diagnostic logging to help debug missing files
                try:
                    files = os.listdir(analysis_dir)
                except Exception as e:
                    files = [f"(failed to list dir: {str(e)})"]
                logger.error(f"Analysis result file not found for function {function_name}. Directory listing: {files}")
                # Log any JSON snippets we can find
                for fn in files:
                    try:
                        if isinstance(fn, str) and fn.endswith('.json'):
                            p = os.path.join(analysis_dir, fn)
                            if os.path.exists(p):
                                with open(p, 'r', encoding='utf-8') as tf:
                                    snippet = tf.read(1024)
                                logger.error(f"JSON file snippet {fn}: {snippet}")
                    except Exception:
                        logger.exception(f"Failed to read json snippet: {fn}")

                detail_msg = (
                    f"Analysis result file not found.\n"
                    f"function_name={function_name}\n"
                    f"analysis_dir={analysis_dir}\n"
                    f"candidates={json_files}\n"
                    f"dir_listing={files}"
                )

                logger.error(detail_msg)
                abort(500, detail_msg)

            
            # 使用最新的结果文件
            json_files.sort(key=os.path.getmtime, reverse=True)
            result_file = json_files[0]
            
            # 读取结果
            with open(result_file, 'r', encoding='utf-8') as f:
                analysis_result = json.load(f)
            
            # 直接返回完整结果，保证结构与生成的 JSON 文件一致（含 data_flow 字段）
            logger.info(f"Successfully retrieved call info for function {function_name}")
            return jsonify(analysis_result), 200
            
        except subprocess.TimeoutExpired:
            logger.error("IDA analysis timed out")
            abort(408, "Analysis timeout")
        except Exception as e:
            logger.error(f"Error getting function call info: {str(e)}", exc_info=True)
            abort(500, f"Failed to get function call info: {str(e)}")
            
    except Exception as e:
        logger.error(f"Error in get_function_call_info: {str(e)}", exc_info=True)
        abort(500, f"Internal server error: {str(e)}")


@app.route('/export_strings', methods=['POST'])
def export_strings():
    """上传单个二进制并导出硬编码字符串(JSON)。"""
    try:
        if request.content_length and request.content_length > MAX_FILE_SIZE:
            abort(413, "File too large")

        uploaded_file = request.files.get('file')
        if not uploaded_file or uploaded_file.filename == '':
            abort(400, "No valid file uploaded")

        ida_version = request.form.get('ida_version', 'ida').lower()
        IDAT_PATH = IDAT64_PATH if ida_version == 'ida64' else IDAT32_PATH

        date_str = datetime.now().strftime('%Y%m%d')
        analysis_dir = os.path.join(ida_output_dir, date_str)
        os.makedirs(analysis_dir, exist_ok=True)

        bin_path = os.path.join(analysis_dir, uploaded_file.filename)
        uploaded_file.save(bin_path)
        logger.info(f"File saved to: {bin_path}")

        cmd = [
            IDAT_PATH,
            '-A',
            '-T',
            f'-S{EXPORT_STRINGS_SCRIPT}',
            bin_path
        ]

        logger.info(f"Executing: {' '.join(cmd)}")
        proc_env = os.environ.copy()
        proc_env.update({
            "PYTHONHOME": PYTHONHOME,
            "PYTHONPATH": PYTHONPATH
        })

        try:
            result = subprocess.run(
                cmd,
                cwd=analysis_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=TIMEOUT,
                env=proc_env,
            )
        except subprocess.TimeoutExpired:
            abort(408, "Analysis timeout")

        if result.returncode != 0:
            error_msg = (result.stderr or "").strip()
            logger.error(f"IDA export_strings failed: {error_msg}")
            abort(500, f"IDA analysis failed: {error_msg}")

        output_path = os.path.join(analysis_dir, f"{uploaded_file.filename}_strings.json")
        if not os.path.exists(output_path):
            logger.error(f"String export file not found: {output_path}")
            abort(500, "String export file not generated")

        with open(output_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        return jsonify(data)

    except Exception as e:
        logger.error(f"Error during string export: {str(e)}", exc_info=True)
        abort(500, f"String export error: {str(e)}")


@app.route("/string_context", methods=["POST"])
def string_context():
    """
    对可疑字符串进行交叉引用分析，获取代码上下文
    
    请求参数:
    - binary_path: 二进制文件路径（可以是客户端路径，会自动提取文件名在服务端查找）
    - binary_name: 二进制文件名（可选，直接指定文件名）
    - strings: 可疑字符串列表，每个元素包含:
        - value: 字符串值
        - address: 字符串地址（可选，十六进制字符串如 "0x12345"）
        - vaddr: 虚拟地址（可选）
    - max_xrefs: 每个字符串最大交叉引用数量（默认10）
    
    返回:
    - results: 分析结果列表，包含交叉引用和反编译代码上下文
    """
    try:
        # 获取请求参数
        if request.is_json:
            data = request.get_json()
            binary_path = data.get("binary_path", "")
            binary_name = data.get("binary_name", "")
            strings = data.get("strings", [])
            max_xrefs = data.get("max_xrefs", 10)
        else:
            binary_path = request.form.get("binary_path", "")
            binary_name = request.form.get("binary_name", "")
            strings = json.loads(request.form.get("strings", "[]"))
            max_xrefs = int(request.form.get("max_xrefs", 10))
        
        # 从 binary_path 提取文件名（如果没有直接提供 binary_name）
        if not binary_name and binary_path:
            # 处理 Linux 和 Windows 路径
            binary_name = os.path.basename(binary_path.replace('\\', '/'))
        
        if not binary_name:
            abort(400, "Missing binary_path or binary_name parameter")
        
        if not strings:
            abort(400, "Missing strings parameter")
        
        logger.info(f"String context analysis: binary_name={binary_name}, {len(strings)} strings")
        
        # 在当天目录下查找二进制文件和IDB
        date_str = datetime.now().strftime('%Y%m%d')
        analysis_dir = os.path.join(ida_output_dir, date_str)
        
        if not os.path.exists(analysis_dir):
            abort(404, f"Analysis directory not found: {analysis_dir}")
        
        # 查找二进制文件
        bin_path = os.path.join(analysis_dir, binary_name)
        if not os.path.exists(bin_path):
            # 尝试在子目录中查找
            for root, dirs, files in os.walk(analysis_dir):
                if binary_name in files:
                    bin_path = os.path.join(root, binary_name)
                    break
            else:
                abort(404, f"Binary file not found in today's analysis directory: {binary_name}")
        
        logger.info(f"Found binary at: {bin_path}")
        
        # 检查是否有对应的IDB文件
        idb_path = None
        for ext in ['.i64', '.idb']:
            potential_idb = bin_path + ext
            if os.path.exists(potential_idb):
                idb_path = potential_idb
                break
        
        if not idb_path:
            abort(400, f"No IDB file found for {binary_name}. Please analyze the binary first with /export_strings.")
        
        logger.info(f"Using IDB: {idb_path}")
        
        try:
            # 构建IDA命令
            # 使用 -A 自动分析模式，-S 运行脚本
            # 根据IDB类型选择32位或64位IDA
            if idb_path.endswith('.i64'):
                IDA_PATH = IDA64_PATH
            else:
                IDA_PATH = IDA32_PATH
            
            # 将输入输出文件放在与IDB相同的目录，使用固定名称
            # IDAPython脚本将自动查找这些文件
            idb_dir = os.path.dirname(idb_path)
            idb_basename = os.path.basename(idb_path)
            
            # 使用IDB名称作为前缀的输入输出文件
            input_file_in_idb_dir = os.path.join(idb_dir, f"{idb_basename}_xref_input.json")
            output_file_in_idb_dir = os.path.join(idb_dir, f"{idb_basename}_xref_output.json")
            
            # 写入输入文件
            with open(input_file_in_idb_dir, 'w', encoding='utf-8') as f:
                json.dump({
                    "strings": strings,
                    "max_xrefs": max_xrefs
                }, f, ensure_ascii=False)
            
            logger.info(f"Input file written to: {input_file_in_idb_dir}")
            
            # 使用环境变量传递参数给 IDAPython 脚本
            proc_env = os.environ.copy()
            proc_env.update({
                "PYTHONHOME": PYTHONHOME,
                "PYTHONPATH": PYTHONPATH,
                "IDA_INPUT_FILE": input_file_in_idb_dir,
                "IDA_OUTPUT_FILE": output_file_in_idb_dir,
            })
            
            # 注意：使用原始二进制文件路径，IDA会自动加载同目录下的IDB
            # 如果直接传IDB文件，脚本可能不会执行
            ida_cmd = [
                IDA_PATH,
                "-A",  # 自动模式
                f'-S{STRING_XREF_SCRIPT}',  # 注意：不要用引号，subprocess.run会自动处理
                bin_path  # 使用原始二进制，不是IDB
            ]
            
            logger.info(f"Running IDA command: {' '.join(ida_cmd)}")
            logger.info(f"Input file: {input_file_in_idb_dir}")
            logger.info(f"Output file: {output_file_in_idb_dir}")
            
            # 执行IDA
            result = subprocess.run(
                ida_cmd,
                capture_output=True,
                text=True,
                timeout=TIMEOUT,
                env=proc_env,
                cwd=idb_dir  # 在IDB目录下执行
            )
            
            # 打印IDA输出以便调试
            if result.stdout:
                logger.info(f"IDA stdout: {result.stdout[:1000]}")
            if result.stderr:
                logger.error(f"IDA stderr: {result.stderr[:1000]}")
            
            if result.returncode != 0:
                logger.error(f"IDA return code: {result.returncode}")
                # IDA可能返回非0但仍然成功生成了输出
                if not os.path.exists(output_file_in_idb_dir):
                    # 检查是否有错误文件
                    error_file = os.path.join(idb_dir, "string_xref_error.txt")
                    if os.path.exists(error_file):
                        with open(error_file, 'r') as f:
                            error_content = f.read()
                        logger.error(f"IDAPython error: {error_content}")
                    abort(500, f"IDA analysis failed: {result.stderr}")
            
            # 读取结果
            if os.path.exists(output_file_in_idb_dir):
                with open(output_file_in_idb_dir, 'r', encoding='utf-8') as f:
                    context_results = json.load(f)
                
                # 清理临时文件
                try:
                    os.remove(input_file_in_idb_dir)
                    os.remove(output_file_in_idb_dir)
                except:
                    pass
                
                return jsonify({
                    "status": "success",
                    "binary_path": binary_path,
                    "idb_path": idb_path,
                    "results": context_results
                })
            else:
                abort(500, "IDA did not produce output file")
                
        except subprocess.TimeoutExpired:
            logger.error(f"IDA timeout after {TIMEOUT} seconds")
            # 清理临时文件
            try:
                if os.path.exists(input_file_in_idb_dir):
                    os.remove(input_file_in_idb_dir)
            except:
                pass
            abort(504, f"IDA analysis timed out after {TIMEOUT} seconds")
                
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {str(e)}")
        abort(400, f"Invalid JSON in strings parameter: {str(e)}")
    except Exception as e:
        logger.error(f"Error in string_context: {str(e)}", exc_info=True)
        abort(500, f"Internal server error: {str(e)}")


# ==================== 新增 API 端点（用于 ReAct Agent）====================

@app.route('/export_call_graph', methods=['POST'])
def export_call_graph():
    """
    导出二进制的函数调用图
    
    请求参数:
    - binary_name: 二进制文件名
    - ida_version: IDA版本 (ida/ida64)
    
    返回:
    - JSON 格式的调用图，包含 nodes（函数）和 edges（调用关系）
    """
    try:
        binary_name = request.form.get('binary_name')
        if not binary_name:
            abort(400, "Missing binary_name parameter")
        
        ida_version = request.form.get('ida_version', 'ida').lower()
        IDAT_PATH = IDAT64_PATH if ida_version == 'ida64' else IDAT32_PATH
        
        # 查找二进制文件
        date_str = datetime.now().strftime('%Y%m%d')
        analysis_dir = os.path.join(ida_output_dir, date_str)
        bin_path = os.path.join(analysis_dir, binary_name)
        
        if not os.path.exists(bin_path):
            abort(404, f"Binary file not found: {binary_name}")
        
        # 调用图脚本路径
        call_graph_script = os.path.abspath("export_call_graph.py")
        
        cmd = [
            IDAT_PATH,
            '-A',
            '-T',
            f'-S{call_graph_script}',
            bin_path
        ]
        
        logger.info(f"Executing call graph export: {' '.join(cmd)}")
        
        proc_env = os.environ.copy()
        proc_env.update({
            "PYTHONHOME": PYTHONHOME,
            "PYTHONPATH": PYTHONPATH
        })
        
        try:
            result = subprocess.run(
                cmd,
                cwd=analysis_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=TIMEOUT,
                env=proc_env,
            )
        except subprocess.TimeoutExpired:
            abort(408, "Call graph export timeout")
        
        if result.returncode != 0:
            error_msg = (result.stderr or "").strip()
            logger.error(f"Call graph export failed: {error_msg}")
            abort(500, f"Call graph export failed: {error_msg}")
        
        # 读取输出文件
        output_path = os.path.join(analysis_dir, f"{binary_name}_call_graph.json")
        if not os.path.exists(output_path):
            abort(500, "Call graph output file not generated")
        
        with open(output_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        return jsonify(data)
    
    except Exception as e:
        logger.error(f"Error in export_call_graph: {str(e)}", exc_info=True)
        abort(500, f"Call graph export error: {str(e)}")


@app.route('/get_function_xrefs', methods=['POST'])
def get_function_xrefs():
    """
    获取函数的交叉引用信息（调用者/被调用者）
    
    请求参数:
    - binary_name: 二进制文件名
    - function_name: 目标函数名
    - xref_type: 引用类型 ("caller" 或 "callee")
    - depth: 递归深度 (默认 1)
    - ida_version: IDA版本 (ida/ida64)
    
    返回:
    - JSON 格式的交叉引用信息
    """
    try:
        binary_name = request.form.get('binary_name')
        function_name = request.form.get('function_name')
        xref_type = request.form.get('xref_type', 'caller')
        depth = request.form.get('depth', '1')
        
        if not binary_name or not function_name:
            abort(400, "Missing binary_name or function_name parameter")
        
        ida_version = request.form.get('ida_version', 'ida').lower()
        IDAT_PATH = IDAT64_PATH if ida_version == 'ida64' else IDAT32_PATH
        
        # 查找二进制文件
        date_str = datetime.now().strftime('%Y%m%d')
        analysis_dir = os.path.join(ida_output_dir, date_str)
        bin_path = os.path.join(analysis_dir, binary_name)
        
        if not os.path.exists(bin_path):
            abort(404, f"Binary file not found: {binary_name}")
        
        # 交叉引用脚本路径
        xref_script = os.path.abspath("get_function_xrefs.py")
        
        # 设置环境变量传递参数
        proc_env = os.environ.copy()
        proc_env.update({
            "PYTHONHOME": PYTHONHOME,
            "PYTHONPATH": PYTHONPATH,
            "XREF_FUNCTION_NAME": function_name,
            "XREF_TYPE": xref_type,
            "XREF_DEPTH": str(depth)
        })
        
        cmd = [
            IDAT_PATH,
            '-A',
            '-T',
            f'-S{xref_script}',
            bin_path
        ]
        
        logger.info(f"Executing xref analysis: {' '.join(cmd)} | func={function_name} type={xref_type}")
        
        try:
            result = subprocess.run(
                cmd,
                cwd=analysis_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=TIMEOUT,
                env=proc_env,
            )
        except subprocess.TimeoutExpired:
            abort(408, "Xref analysis timeout")
        
        if result.returncode != 0:
            error_msg = (result.stderr or "").strip()
            logger.error(f"Xref analysis failed: {error_msg}")
            abort(500, f"Xref analysis failed: {error_msg}")
        
        # 读取输出文件
        output_path = os.path.join(analysis_dir, f"{binary_name}_{function_name}_xrefs.json")
        if not os.path.exists(output_path):
            abort(500, "Xref output file not generated")
        
        with open(output_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        return jsonify(data)
    
    except Exception as e:
        logger.error(f"Error in get_function_xrefs: {str(e)}", exc_info=True)
        abort(500, f"Xref analysis error: {str(e)}")


    
@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(408)
@app.errorhandler(410)
@app.errorhandler(500)
def handle_error(error):
    logger.error(f"Error {error.code}: {error.description}")
    return {
        "status": "error",
        "code": error.code,
        "message": error.description
    }, error.code


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=port)
