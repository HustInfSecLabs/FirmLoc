from flask import Flask, request, send_file, abort, jsonify
import tempfile
import os, sys, zipfile
import subprocess
import shutil
import logging
from datetime import datetime
import pyautogui
import time
import json
import re

# Flask服务端口
port = 5000

# 配置 PYTHONHOME 和 PYTHONPATH 环境变量
PYTHONHOME = r"C:\Users\WangZihao\AppData\Local\Programs\Python\Python313"
PYTHONPATH = r"C:\Users\WangZihao\AppData\Local\Programs\Python\Python313\Lib;C:\Users\WangZihao\AppData\Local\Programs\Python\Python313\DLLs"

# 配置ida、idat路径
IDA32_PATH = r"C:\tools\IDA\ida.exe"  # ida32安装路径
IDA64_PATH = r"C:\tools\IDA\ida.exe"  # ida64安装路径
IDAT32_PATH = r"C:\tools\IDA\idat.exe"
IDAT64_PATH = r"C:\tools\IDA\idat.exe"

# 配置分析脚本路径, 确保绝对路径
BINEXPORT_SCRIPT = os.path.abspath("export_binexport.py")
EXPORT_SCRIPT = os.path.abspath("export_hexrays.py")
ANALYZE_SCRIPT = os.path.abspath("analyze.py")
WAIT_SCRIPT = os.path.abspath("wait_for_analysis.py")

# 最大文件大小限制
MAX_FILE_SIZE = 1024 * 1024 * 500  # 500MB
TIMEOUT = 3000  # 50分钟超时

# 导出伪C代码的等待检测时间
max_wait_time = 30  # 最大等待时间（秒）
check_interval = 0.5  # 检查间隔（秒）

# 配置日志记录
def setup_logger():
    # 创建log目录
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "log")
    os.makedirs(log_dir, exist_ok=True)
    
    # 设置日志文件名
    log_file = os.path.join(log_dir, f"{datetime.now().strftime('%Y%m%d')}.log")
    
    # 配置日志格式和级别
    logging.basicConfig(
        level=logging.DEBUG,
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
   
def take_screenshot(filename: str, stage="disassembly"):
    """
    获取当前屏幕截图并保存到日期目录
    
    参数:
        stage (str): 截图阶段标识，可选值:
            - "disassembly" (默认): 反汇编阶段
            - "decompilation": 反编译阶段
    
    返回:
        str: 截图文件路径，失败时返回None
    """
    try:
        # 验证stage参数
        if stage not in ["disassembly", "decompilation"]:
            raise ValueError(f"Invalid stage value: {stage}. Must be 'disassembly' or 'decompilation'")
        

        # 创建日期格式的子目录
        date_str = datetime.now().strftime('%Y%m%d')
        screenshot_dir = os.path.join(ida_output_dir, date_str, "screenshots")
        
        # 确保目录存在
        os.makedirs(screenshot_dir, exist_ok=True)
        
        # 生成带时间戳和阶段标识的文件名
        timestamp = datetime.now().strftime('%H%M%S')
        stage_marker = "asm" if stage == "disassembly" else "decomp"
        screenshot_path = os.path.join(
            screenshot_dir, 
            f"{filename}_{stage_marker}_{timestamp}.png"
        )
        
        # 获取屏幕截图
        pyautogui.screenshot(screenshot_path)
        logger.info(f"Saved {stage} screenshot to: {screenshot_path}")
        return screenshot_path
    except ValueError as ve:
        logger.error(f"Invalid parameter: {str(ve)}")
        return None
    except Exception as e:
        logger.error(f"Error taking screenshot: {str(e)}")
        return None
    

@app.route('/reversing_analyze_screenshot', methods=['POST'])
def analyze_with_screenshot():
    """分析二进制文件并返回IDA屏幕截图"""
    # 检查文件大小
    if request.content_length > MAX_FILE_SIZE:
        abort(413, "File too large (max 100MB)")
    
    # 获取IDA版本参数 (默认为ida32)
    ida_version = request.form.get('ida_version', 'ida').lower()
    if ida_version == 'ida64':
        print("Using IDA64")
        IDA_PATH = IDA64_PATH
    else:
        IDA_PATH = IDA32_PATH
    
    # 创建基于日期的目录
    date_str = datetime.now().strftime('%Y%m%d')
    analysis_dir = os.path.join(ida_output_dir, date_str)
    os.makedirs(analysis_dir, exist_ok=True)
    logger.info(f"Using analysis dir: {analysis_dir}")
    
    try:
        # 保存上传文件
        uploaded_file = request.files['file']
        if not uploaded_file or uploaded_file.filename == '':
            abort(400, "No valid file uploaded")
        
        # 保存文件到ida_output_dir下的当天日期目录
        bin_path = os.path.join(analysis_dir, uploaded_file.filename)
        uploaded_file.save(bin_path)
        logger.info(f"File saved to: {bin_path}")
        
        # 运行IDA分析
        marker_path = os.path.join(analysis_dir, "analysis_done.marker")
        cmd = [
            IDA_PATH,
            '-A',  # 自动模式
            f'-S"{WAIT_SCRIPT}"',
            bin_path
        ]
        print(cmd)
        
        try:
            # 启动IDA进程
            env = {
                "PATH": os.environ["PATH"],
                "SYSTEMROOT": os.environ["SYSTEMROOT"],
                "PYTHONHOME": PYTHONHOME,
                "PYTHONPATH": PYTHONPATH,
                "IDA_ANALYSIS_MARKER": marker_path
            }
            ida_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            
            # 等待IDA分析完成（检查marker文件）
            logger.info("Waiting for IDA analysis to complete...")
            start_wait = time.time()
            analysis_completed = False
            while time.time() - start_wait < 300:  # 最多等待5分钟
                if os.path.exists(marker_path):
                    analysis_completed = True
                    break
                if ida_process.poll() is not None:
                    logger.error("IDA process exited unexpectedly")
                    break
                time.sleep(1)
            
            if not analysis_completed:
                logger.warning("Analysis timeout or failed, proceeding with screenshots anyway")
            else:
                logger.info(f"Analysis completed in {time.time() - start_wait:.2f} seconds")
            
            # 获取反汇编的截图
            screenshot_path_1 = take_screenshot(filename=uploaded_file.filename, stage="disassembly")
            if not screenshot_path_1:
                abort(500, "Failed to capture first screenshot")

            # 模拟Tab键输入，进行反编译
            pyautogui.press('tab')
            time.sleep(1)
            
            # 获取反编译的截图
            screenshot_path_2 = take_screenshot(filename=uploaded_file.filename, stage="decompilation")
            if not screenshot_path_2:
                abort(500, "Failed to capture second screenshot")
            
            # 终止IDA进程，否则终端会卡住
            ida_process.terminate()
            try:
                ida_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                ida_process.kill()
            
            # 检查截图是否存在
            if not (os.path.exists(screenshot_path_1) or not os.path.exists(screenshot_path_2)):
                abort(500, "Screenshot files not generated")
            
            # 创建zip文件
            zip_filename = os.path.join(analysis_dir, f"ida_screenshots_{uploaded_file.filename}.zip")
            with zipfile.ZipFile(zip_filename, 'w') as zipf:
                zipf.write(screenshot_path_1, os.path.basename(screenshot_path_1))
                zipf.write(screenshot_path_2, os.path.basename(screenshot_path_2))
            
            # 返回zip文件
            return send_file(
                zip_filename,
                as_attachment=True,
                download_name=f"ida_screenshots_{uploaded_file.filename}.zip",
                mimetype='application/zip'
            )
            
        except subprocess.TimeoutExpired:
            abort(408, "Analysis timeout")
        except Exception as e:
            logger.error(f"Error during IDA analysis: {str(e)}")
            abort(500, f"IDA analysis error: {str(e)}")
            
    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}")
        abort(500, f"Analysis error: {str(e)}")


@app.route('/export_binexport', methods=['POST'])
def analyze():
    """根据文件名分析已存在的二进制文件"""
    try:
        # 获取请求参数
        binary_name = request.form.get('binary_name')
        if not binary_name:
            abort(400, "No binary name provided")
        
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
        
        # 检查目录是否存在
        if not os.path.exists(analysis_dir):
            abort(404, f"Analysis directory not found: {analysis_dir}")
        
        # 查找目标文件
        bin_path = os.path.join(analysis_dir, binary_name)
        if not bin_path:
            abort(404, f"Binary file not found: {binary_name}")
        
        logger.info(f"Found target file: {bin_path}")
        
        # 运行IDA分析
        cmd = [
            IDAT_PATH,
            '-A',  # 自动模式
            '-T',  # 不显示界面
            f'-S\"{BINEXPORT_SCRIPT}\"',  # 执行脚本
            bin_path
        ]
        logger.info(f"Executing: {' '.join(cmd)}")
        
        try:
            proc_env = os.environ.copy()
            proc_env.update({
                "PYTHONHOME": PYTHONHOME,
                "PYTHONPATH": PYTHONPATH
            })
            result = subprocess.run(
                cmd,
                cwd=analysis_dir,  # 在工作目录执行
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=TIMEOUT,
                env=proc_env,
            )
        except subprocess.TimeoutExpired:
            abort(408, "Analysis timeout")
        
        # 检查执行结果
        if result.returncode != 0:
            error_msg = result.stderr.decode().strip()
            logger.error(f"IDA Error (code {result.returncode}): {error_msg}")
            abort(500, f"IDA analysis failed: {error_msg}")
        
        logger.info(f"Analysis completed successfully")
        
        # 获取生成文件（假设脚本生成同名的.BinExport文件）
        export_path = bin_path + '.BinExport'
        if ida_version == 'ida64':
            idb_path = bin_path + '.i64'
        else:
            idb_path = bin_path + '.idb'
        logger.info(f"Looking for export file: {export_path} and idb file: {idb_path}")
        logger.info(f"Export file exists: {os.path.exists(export_path)}")
        if not os.path.exists(export_path):
            logger.error(f"Export file not found: {export_path} or {idb_path}")
            abort(500, f"BinExport file not generated: {export_path}")
        
        # 创建zip文件
        zip_filename = os.path.join(analysis_dir, f"ida_analysis_{binary_name}.zip")
        with zipfile.ZipFile(zip_filename, 'w') as zipf:
            zipf.write(export_path, os.path.basename(export_path))
            # zipf.write(idb_path, os.path.basename(idb_path))

        # 返回zip文件
        return send_file(
            zip_filename,
            as_attachment=True,
            download_name=f"ida_analysis_{binary_name}.zip",
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
        if not binary_name:
            abort(400, "No binary name provided")

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
        source_output_dir = os.path.join(analysis_dir, "source")
        os.makedirs(source_output_dir, exist_ok=True)

        # 查找目标文件
        bin_path = os.path.join(analysis_dir, binary_name)
        if not bin_path:
            abort(404, f"Binary file not found: {binary_name}")

        logger.info(f"Found target file: {bin_path}")

        # 运行IDA分析
        cmd = [
            IDAT_PATH,
            '-A',  # 自动模式
            '-T',  # 不显示界面
            f'-S\"{EXPORT_SCRIPT}\"',
            bin_path
        ]
        logger.info(f"Executing: {' '.join(cmd)}")
        
        start_time = time.time()
        try:
            result = subprocess.run(
                cmd,
                # cwd=analysis_dir,  # 在工作目录执行
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=TIMEOUT,
                env={
                    "PATH": os.environ["PATH"],
                    "SYSTEMROOT": os.environ["SYSTEMROOT"],
                    "PYTHONHOME": PYTHONHOME,
                    "PYTHONPATH": PYTHONPATH
                },
            )
        except subprocess.TimeoutExpired:
            # abort(408, "Export pseudo C timeout")
            logger.warning("Export pseudo C timeout")
        
        end_time = time.time()
        
        # 再次检查输出文件
        output_filepath = os.path.join(analysis_dir, f"{binary_name}_pseudo.c")
        if not os.path.exists(output_filepath):
            abort(500, f"Pseudo C file not generated: {output_filepath}")
        
        pseudo_filepath = os.path.join(source_output_dir, f"{binary_name}_pseudo.c")
        if os.path.exists(pseudo_filepath):
            os.remove(pseudo_filepath)
        shutil.move(output_filepath, source_output_dir)
        

        logger.info(f"{binary_name} Exported pseudo C completed, size: {convert_size(os.path.getsize(bin_path))}")
        logger.info(f"Export time: {end_time - start_time:.2f} seconds")

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
            proc_env.update({
                "PYTHONHOME": PYTHONHOME,
                "PYTHONPATH": PYTHONPATH,
                "IDA_FUNC_NAME": function_name  # 通过环境变量传递函数名
            })
            
            logger.debug(f"Environment variables: IDA_FUNC_NAME={function_name}")

            result = subprocess.run(
                cmd,
                cwd=analysis_dir,  # 在工作目录执行
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=TIMEOUT,
                env=proc_env,
            )
            
            stdout_text = result.stdout.decode(errors='ignore').strip()
            stderr_text = result.stderr.decode(errors='ignore').strip()

            if stdout_text:
                logger.debug(f"IDA stdout: {stdout_text}")
            if stderr_text:
                logger.debug(f"IDA stderr: {stderr_text}")

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
                logger.error(f"Analysis result file not found for function {function_name}")
                abort(500, "Analysis result file not found")
            
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
     

if __name__ == '__main__':
    from waitress import serve
    serve(app, host="0.0.0.0", port=port)

