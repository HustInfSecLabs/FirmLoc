from flask import Flask, request, send_file, abort
import tempfile
import os, sys
import subprocess
import shutil
import logging
from datetime import datetime

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

# 配置参数
IDA32_PATH = r"D:\software\IDA_Pro_v7.5_Portable\ida"  # ida32安装路径
IDA64_PATH = r"D:\software\IDA_Pro_v7.5_Portable\ida64"  # ida64安装路径
ANALYZE_SCRIPT = os.path.abspath("export_binexport.py")  # 确保绝对路径

print(ANALYZE_SCRIPT)

MAX_FILE_SIZE = 1024 * 1024 * 100  # 100MB
TIMEOUT = 300  # 5分钟超时


@app.route('/analyze', methods=['POST'])
def analyze():
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
    
    # 创建输出目录 (与程序同路径)
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ida_output")
    os.makedirs(output_dir, exist_ok=True)
    
    # 创建带时间戳的子目录
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    temp_dir = os.path.join(output_dir, f"analysis_{timestamp}")
    os.makedirs(temp_dir, exist_ok=True)
    app.logger.info(f"Created output dir: {temp_dir}")
    
    try:
        # 保存上传文件
        uploaded_file = request.files['file']
        if not uploaded_file or uploaded_file.filename == '':
            abort(400, "No valid file uploaded")
        
        bin_path = os.path.join(temp_dir, uploaded_file.filename)
        uploaded_file.save(bin_path)
        app.logger.info(f"File saved to: {bin_path}")
        
        # 运行IDA分析
        cmd = [
            IDA_PATH,
            '-A',  # 自动模式
            '-T',
            f'-S{ANALYZE_SCRIPT}',  # 执行脚本
            bin_path
        ]
        print(cmd)
        
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=TIMEOUT,
                env={
                    "PATH": os.environ["PATH"],
                    "SYSTEMROOT": os.environ["SYSTEMROOT"],
                    # 强制指定 Python 环境
                    "PYTHONHOME": r"C:\ProgramData\Miniconda3",
                    "PYTHONPATH": r"C:\ProgramData\Miniconda3\Lib;C:\ProgramData\Miniconda3\DLLs"
                },
            )
        except subprocess.TimeoutExpired:
            abort(408, "Analysis timeout")
        
        # 检查执行结果
        if result.returncode != 0:
            app.logger.error(f"IDA Error:\n{result.stderr.decode()}")
            abort(500, "IDA analysis failed")
        else:
            app.logger.info(f"IDA analysis completed successfully")
            app.logger.info(f"IDA Output:\n{result.stdout.decode()}")
        
        # 获取生成文件
        export_path = bin_path + '.export'
        if not os.path.exists(export_path):
            abort(500, "Export file not generated")
        
        # 返回结果
        return send_file(
            export_path,
            as_attachment=True,
            download_name=os.path.basename(export_path))
        
    except Exception as e:
        app.logger.error(f"Error during analysis: {str(e)}")
        abort(500, f"Analysis error: {str(e)}")

if __name__ == '__main__':
    from waitress import serve
    serve(app, host="0.0.0.0", port=5000)
