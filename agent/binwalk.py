import os
import subprocess
import json
import configparser
from pathlib import Path
from .base import Agent
from model import ChatModel
from datetime import datetime
import glob
import asyncio
from utils import ConfigManager

class BinwalkAgent(Agent):
    """
    调用binwalk工具对固件文件进行分析和提取
    """
    
    def __init__(self, chat_model: ChatModel) -> None:
        super().__init__(chat_model)
        self.agent = "Binwalk Agent"
        self.tool = "Binwalk"
        self.tool_status = "stop"
        self.command = None
        self.tool_result = None
        self.tool_type = "terminal"

        
    async def process(self, task_id: str, firmware_path: str, config: ConfigManager, send_message=None, on_status_update=None) -> str:
        if not task_id or not firmware_path:
            return json.dumps({
                'status': 'error',
                'message': '缺少必要参数: task_id 或 firmware_path'
            })
            
        if not os.path.exists(firmware_path):
            return json.dumps({
                'status': 'error',
                'message': f'固件文件不存在: {firmware_path}'
            })
        
        firmware_name = os.path.basename(firmware_path)
        
        work_dir = Path(f'./history/{task_id}/binwalk')
        os.makedirs(work_dir, exist_ok=True)
        
        firmware_dir = work_dir / firmware_name
        os.makedirs(firmware_dir, exist_ok=True)
        
        try:
            # 执行binwalk -e进行分析和提取
            extract_cmd = ['binwalk', '-Me', firmware_path]
            extract_path = firmware_dir  # 运行binwalk提取的目录路径
            # 更新状态
            config.update_tool_status("Online Search", "Binwalk")
            self.tool_status = "running"
            if on_status_update:
                on_status_update(' '.join(extract_cmd), self.tool, self.tool_status)
            tool_content = [
                {
                    "user": "wzh@ubuntu:~$",
                    "input": ' '.join(extract_cmd),
                    "output": None
                }
            ]
            # asyncio.create_task(send_message(
            #     f"正在执行: {' '.join(extract_cmd)}", 
            #     "command", 
            #     self.tool_type, 
            #     tool_content,
            #     agent=self.agent,
            #     tool=self.tool,
            #     tool_status=self.tool_status))
            os.makedirs(extract_path, exist_ok=True)
            
            result_output = subprocess.run(
                extract_cmd,
                capture_output=True,
                text=True,
                check=True,
                cwd=str(extract_path)
            )

            if result_output.returncode != 0:
                raise RuntimeError(f"binwalk 执行失败: {result_output.returncode}")
            
            extracted_dirs = sorted(glob.glob(f"{extract_path}/_{firmware_name}*.extracted"), key=os.path.getmtime)

            if not extracted_dirs:
                raise RuntimeError("binwalk 未提取出任何目录")

            actual_extracted_path = extracted_dirs[-1]  # 实际提取完成后提取出的文件夹路径
            
            # 更新状态
            config.update_tool_status("Binwalk")
            self.tool_status = "completed"
            on_status_update(tool_status = self.tool_status)
            tool_content[0]["output"] = result_output.stdout
            # asyncio.create_task(send_message(
            #     f"{' '.join(extract_cmd)}", 
            #     "command", 
            #     self.tool_type, 
            #     tool_content,
            #     agent=self.agent,
            #     tool=self.tool,
            #     tool_status=self.tool_status))
            if send_message:
                await send_message(
                        f"{' '.join(extract_cmd)}", 
                        "command", 
                        self.tool_type, 
                        tool_content,
                        agent=self.agent,
                        tool=self.tool,
                        tool_status=self.tool_status)
            # asyncio.create_task(asyncio.sleep(1))  # 确保消息发送完成
                await asyncio.sleep(1)
            # 保存终端输出结果
            with open(firmware_dir / 'binwalk_result.txt', 'w') as f:
                f.write(result_output.stdout)
            
            # 准备结果数据
            result = {
                'status': 'success',
                'binwalk_result_path': str(firmware_dir / 'binwalk_result.txt'),
                'extracted_files_path': str(actual_extracted_path)
            }
            
            # 更新状态
            self._update_status_ini(work_dir, firmware_name, result)
                
            return result
            
        except Exception as e:
            error_result = {
                'status': 'error',
                'message': f'执行过程中发生错误: {str(e)}'
            }
            
            # 更新状态
            self._update_status_ini(work_dir, firmware_name, error_result)
                
            return json.dumps(error_result)
    
    def _update_status_ini(self, work_dir, firmware_name, result):
        """更新状态"""
        status_file = work_dir / 'status.ini'
        
        config = configparser.ConfigParser()
        if os.path.exists(status_file):
            config.read(status_file)
        
        if config.has_section(firmware_name):
            config.remove_section(firmware_name)
        
        config.add_section(firmware_name)
        
        for key, value in result.items():
            config.set(firmware_name, key, str(value))
        
        with open(status_file, 'w') as f:
            config.write(f)
    
    def get_result(self, task_id: str, firmware_name=None) -> dict:
        work_dir = Path(f'./history/{task_id}/binwalk')
        status_file = work_dir / 'status.ini'
        
        if not os.path.exists(status_file):
            return {
                'status': 'unknown',
                'message': f'未找到任务 {task_id} 的处理结果'
            }
        
        config = configparser.ConfigParser()
        config.read(status_file)
        
        if firmware_name is not None:
            # 返回特定固件的结果
            if firmware_name in config.sections():
                return {key: value for key, value in config[firmware_name].items()}
            else:
                return {
                    'status': 'unknown',
                    'message': f'未找到固件 {firmware_name} 的处理结果'
                }
        else:
            # 返回所有固件的结果
            results = {}
            for section in config.sections():
                results[section] = {key: value for key, value in config[section].items()}
            
            return results
