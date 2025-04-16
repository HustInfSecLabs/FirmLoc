import os
import subprocess
import json
from pathlib import Path
from .base import Agent
from model import ChatModel

class BinwalkAgent(Agent):
    """
    调用binwalk工具对固件文件进行分析和提取
    """
    
    def __init__(self, chat_model: ChatModel) -> None:
        super().__init__(chat_model)
        
    def process(self, task: dict) -> str:
        # 任务ID和固件路径
        task_id = task.get('id')
        firmware_path = task.get('firmware_path')
        
        if not task_id or not firmware_path:
            return json.dumps({
                'status': 'error',
                'message': '缺少必要参数: id 或 firmware_path'
            })
            
        if not os.path.exists(firmware_path):
            return json.dumps({
                'status': 'error',
                'message': f'固件文件不存在: {firmware_path}'
            })
        
        work_dir = Path(f'./result/{task_id}/binwalk')
        os.makedirs(work_dir, exist_ok=True)
        
        try:
            # 执行binwalk -e进行分析和提取
            extract_cmd = ['binwalk', '-e', firmware_path]
            extract_path = work_dir / 'extracted'
            os.makedirs(extract_path, exist_ok=True)
            
            current_dir = os.getcwd()
            os.chdir(extract_path)
            
            result_output = subprocess.run(
                extract_cmd,
                capture_output=True,
                text=True,
                check=True
            )
            
            os.chdir(current_dir)
            
            # 保存终端输出结果
            with open(work_dir / 'binwalk_result.txt', 'w') as f:
                f.write(result_output.stdout)
            
            # 状态文件
            result = {
                'status': 'success',
                'binwalk_result_path': str(work_dir / 'binwalk_result.txt'),
                'extracted_files_path': str(extract_path)
            }
            
            with open(work_dir / 'status.json', 'w') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
                
            return json.dumps(result)
            
        except Exception as e:
            error_result = {
                'status': 'error',
                'message': f'执行过程中发生错误: {str(e)}'
            }
            
            with open(work_dir / 'status.json', 'w') as f:
                json.dump(error_result, f, ensure_ascii=False, indent=2)
                
            return json.dumps(error_result)
    
    def get_result(self, task_id: str) -> dict:
        work_dir = Path(f'./result/{task_id}/binwalk')
        status_file = work_dir / 'status.json'
        
        if os.path.exists(status_file):
            with open(status_file, 'r') as f:
                return json.load(f)
        
        return {
            'status': 'unknown',
            'message': f'未找到任务 {task_id} 的处理结果'
        }
