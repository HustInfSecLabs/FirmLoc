from flask import Flask, request, send_file, abort
import tempfile
import os, sys, zipfile
import subprocess
import shutil
import logging
from datetime import datetime
import pyautogui
import time


app = Flask(__name__)
app.logger.setLevel(logging.INFO)

# 配置ida、idat路径
IDA32_PATH = r"D:\software\IDA_Pro_v7.5_Portable\ida"  # ida32安装路径
IDA64_PATH = r"D:\software\IDA_Pro_v7.5_Portable\ida64"  # ida64安装路径
IDAT32_PATH = r"D:\software\IDA_Pro_v7.5_Portable\idat"
IDAT64_PATH = r"D:\software\IDA_Pro_v7.5_Portable\idat64"

# 配置分析脚本路径
ANALYZE_SCRIPT = os.path.abspath("export_binexport.py")  # 确保绝对路径
print(ANALYZE_SCRIPT)

# 创建base输出目录：ida_output\{日期}
base_dir = os.path.dirname(os.path.abspath(__file__))
ida_output_dir = os.path.join(base_dir, "ida_output")
os.makedirs(ida_output_dir, exist_ok=True)


MAX_FILE_SIZE = 1024 * 1024 * 500  # 500MB
TIMEOUT = 300  # 5分钟超时

# 导出伪C代码的等待检测时间
max_wait_time = 30  # 最大等待时间（秒）
check_interval = 0.5  # 检查间隔（秒）

    
def take_screenshot(stage="disassembly"):
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
            f"ida_{stage_marker}_{timestamp}.png"
        )
        
        # 获取屏幕截图
        pyautogui.screenshot(screenshot_path)
        app.logger.info(f"Saved {stage} screenshot to: {screenshot_path}")
        return screenshot_path
    except ValueError as ve:
        app.logger.error(f"Invalid parameter: {str(ve)}")
        return None
    except Exception as e:
        app.logger.error(f"Error taking screenshot: {str(e)}")
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
    app.logger.info(f"Using analysis dir: {analysis_dir}")
    
    try:
        # 保存上传文件
        uploaded_file = request.files['file']
        if not uploaded_file or uploaded_file.filename == '':
            abort(400, "No valid file uploaded")
        
        # 保存文件到ida_output_dir下的当天日期目录
        bin_path = os.path.join(analysis_dir, uploaded_file.filename)
        uploaded_file.save(bin_path)
        app.logger.info(f"File saved to: {bin_path}")
        
        # 运行IDA分析
        cmd = [
            IDA_PATH,
            '-A',  # 自动模式
            bin_path
        ]
        print(cmd)
        
        try:
            # 启动IDA进程
            ida_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={
                    "PATH": os.environ["PATH"],
                    "SYSTEMROOT": os.environ["SYSTEMROOT"],
                    "PYTHONHOME": r"C:\ProgramData\Miniconda3",
                    "PYTHONPATH": r"C:\ProgramData\Miniconda3\Lib;C:\ProgramData\Miniconda3\DLLs"
                },
            )
            
            # 等待IDA窗口出现
            time.sleep(4)
            
            # 获取反编译的截图
            screenshot_path_1 = take_screenshot(stage="disassembly")
            if not screenshot_path_1:
                abort(500, "Failed to capture first screenshot")

            # 模拟Tab键输入，进行反编译
            pyautogui.press('tab')
            time.sleep(1)
            
            # 获取反汇编的截图
            screenshot_path_2 = take_screenshot(stage="decompilation")
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
            app.logger.error(f"Error during IDA analysis: {str(e)}")
            abort(500, f"IDA analysis error: {str(e)}")
            
    except Exception as e:
        app.logger.error(f"Error during analysis: {str(e)}")
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
            IDA_PATH = IDA64_PATH
        else:
            IDA_PATH = IDA32_PATH
        
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
        
        app.logger.info(f"Found target file: {bin_path}")
        
        # 运行IDA分析
        cmd = [
            IDA_PATH,
            '-A',  # 自动模式
            '-T',  # 不显示界面
            f'-S\"{ANALYZE_SCRIPT}\"',  # 执行脚本
            bin_path
        ]
        app.logger.info(f"Executing: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                cwd=analysis_dir,  # 在工作目录执行
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=TIMEOUT,
                env={
                    "PATH": os.environ["PATH"],
                    "SYSTEMROOT": os.environ["SYSTEMROOT"],
                    "PYTHONHOME": r"C:\ProgramData\Miniconda3",
                    "PYTHONPATH": r"C:\ProgramData\Miniconda3\Lib;C:\ProgramData\Miniconda3\DLLs"
                },
            )
        except subprocess.TimeoutExpired:
            abort(408, "Analysis timeout")
        
        # 检查执行结果
        if result.returncode != 0:
            error_msg = result.stderr.decode().strip()
            app.logger.error(f"IDA Error (code {result.returncode}): {error_msg}")
            abort(500, f"IDA analysis failed: {error_msg}")
        
        app.logger.info(f"Analysis completed successfully")
        
        # 获取生成文件（假设脚本生成同名的.export文件）
        export_path = os.path.splitext(bin_path)[0] + '.BinExport'
        if not os.path.exists(export_path):
            abort(500, f"Export file not generated: {export_path}")
        
        # 返回结果
        return send_file(
            export_path,
            as_attachment=True,
            download_name=os.path.basename(export_path))
        
    except Exception as e:
        app.logger.error(f"Error during analysis: {str(e)}", exc_info=True)
        abort(500, f"Analysis error: {str(e)}")

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
            app.logger.info("Using IDA64")
            IDAT_PATH = IDAT64_PATH
        else:
            IDAT_PATH = IDAT32_PATH

        # 构建当天日期目录路径
        date_str = datetime.now().strftime('%Y%m%d')
        analysis_dir = os.path.join(ida_output_dir, date_str)
        source_output_dir = os.path.join(analysis_dir, "source")
        
        # 创建伪C代码输出目录（如果不存在）
        os.makedirs(source_output_dir, exist_ok=True)

        # 查找目标文件
        bin_path = os.path.join(analysis_dir, binary_name)
        if not bin_path:
            abort(404, f"Binary file not found: {binary_name}")

        app.logger.info(f"Found target file: {bin_path}")

        # 准备输出文件路径
        # print(f"Pseudo C output directory: {source_output_dir}")
        os.chdir(source_output_dir)  # 切换到输出目录
        output_filename = binary_name

        cmd = [
            IDAT_PATH,
            f'-Ohexrays:{output_filename}:ALL',  # Hex-Rays伪代码导出
            '-A',  # 自动模式
            bin_path
        ]
        print(cmd)
        
        output_filepath = os.path.join(source_output_dir, output_filename + ".c")
        if os.path.exists(output_filepath):
            os.remove(output_filepath)
        
        # 运行IDA Hex-Rays反编译
        app.logger.info(f"Exporting pseudo C to: {output_filename}")    
        try:
            ida_process = subprocess.Popen(
                cmd, 
                # stdout=open(export_log, 'w', encoding='utf-8'), 
                # stderr=subprocess.STDOUT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                # stdout=subprocess.DEVNULL,  # 丢弃输出
                # stderr=subprocess.DEVNULL,  # 丢弃错误
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                env={
                    "PATH": os.environ["PATH"],
                    "SYSTEMROOT": os.environ["SYSTEMROOT"],
                    "PYTHONHOME": r"C:\ProgramData\Miniconda3",
                    "PYTHONPATH": r"C:\ProgramData\Miniconda3\Lib;C:\ProgramData\Miniconda3\DLLs"
            })
            

            # 改进的等待逻辑：优先检查输出文件
            start_time = time.time()
            while True:
                # 检查文件是否已生成
                if os.path.exists(output_filepath):
                    print(f"伪C代码已生成: {output_filepath}")
                    time.sleep(5)  
                    ida_process.terminate()
                    try:
                        ida_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        ida_process.kill()
                    break
                
                # 检查是否超时
                elapsed = time.time() - start_time
                if elapsed >= max_wait_time:
                    # print(f"等待超时({max_wait_time}秒)，文件未生成，终止进程...")
                    ida_process.terminate()
                    try:
                        ida_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        ida_process.kill()
                    break
                
                # 检查进程是否已结束
                if ida_process.poll() is not None:
                    print(f"进程已结束(退出码: {ida_process.returncode})，但文件未生成")
                    break
                
                # 等待下一次检查
                time.sleep(check_interval)
            
        except subprocess.CalledProcessError as e:
            app.logger.error(f"Hex-Rays decompilation failed: {e}")
            abort(500, f"Hex-Rays decompilation failed: {e.stdout.read() if e.stdout else str(e)}")
        
        # 再次检查输出文件
        if not os.path.exists(output_filepath):
            abort(500, f"Pseudo C file not generated: {output_filepath}")

        app.logger.info(f"Successfully exported pseudo C code")

        # 返回生成的伪C代码文件
        return send_file(
            output_filepath,
            as_attachment=True,
            download_name=os.path.basename(output_filename),
            mimetype='text/plain'
        )

    except Exception as e:
        app.logger.error(f"Error during pseudo C export: {str(e)}", exc_info=True)
        abort(500, f"Pseudo C export error: {str(e)}")
     

if __name__ == '__main__':
    from waitress import serve
    serve(app, host="0.0.0.0", port=5000)
