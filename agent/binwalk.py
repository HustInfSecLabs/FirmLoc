import os
import subprocess
import json
import configparser
import traceback
from pathlib import Path
from .base import Agent
from model import ChatModel
import glob
import asyncio
from utils import ConfigManager
from log import logger


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

    async def process(self, task_id: str, firmware_path: str, config: ConfigManager, run_root: str = None, send_message=None, on_status_update=None) -> str:
        if not task_id or not firmware_path:
            return json.dumps({
                'status': 'error',
                'message': '缺少必要参数: task_id 或 firmware_path'
            })

        firmware_path = os.path.abspath(firmware_path)
        if not os.path.exists(firmware_path):
            return json.dumps({
                'status': 'error',
                'message': f'固件文件不存在: {firmware_path}'
            })

        firmware_name = os.path.basename(firmware_path)
        if not run_root:
            return {
                'status': 'error',
                'message': '缺少必要参数: run_root'
            }

        base_root = Path(run_root)
        work_dir = base_root / 'binwalk'
        os.makedirs(work_dir, exist_ok=True)

        firmware_dir = work_dir / firmware_name
        os.makedirs(firmware_dir, exist_ok=True)
        extract_path = firmware_dir
        binwalk_log_file = firmware_dir / 'binwalk_result.txt'

        try:
            # 使用绝对路径，避免 cwd 切换后相对路径失效
            extract_cmd = ['binwalk', '-Me', firmware_path]
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
            os.makedirs(extract_path, exist_ok=True)

            def _run_binwalk() -> tuple[subprocess.CompletedProcess[str], str, str]:
                with open(binwalk_log_file, 'w', encoding='utf-8') as log_f:
                    result_output = subprocess.run(
                        extract_cmd,
                        stdout=log_f,
                        stderr=subprocess.STDOUT,
                        text=True,
                        check=True,
                        timeout=1800,
                        cwd=str(extract_path)
                    )

                extracted_dirs = sorted(glob.glob(f"{extract_path}/_{firmware_name}*.extracted"), key=os.path.getmtime)
                if not extracted_dirs:
                    raise RuntimeError("binwalk 未提取出任何目录")

                actual_extracted_path = extracted_dirs[-1]

                with open(binwalk_log_file, 'r', encoding='utf-8') as log_f:
                    binwalk_output = log_f.read()
                    if len(binwalk_output) > 10240:
                        binwalk_output = "... (输出过长,已截断) ...\n" + binwalk_output[-10240:]

                return result_output, actual_extracted_path, binwalk_output

            result_output, actual_extracted_path, binwalk_output = await asyncio.to_thread(_run_binwalk)

            if result_output.returncode != 0:
                raise RuntimeError(f"binwalk 执行失败: {result_output.returncode}")

            config.update_tool_status("Binwalk")
            self.tool_status = "completed"
            if on_status_update:
                on_status_update(tool_status=self.tool_status)
            tool_content[0]["output"] = binwalk_output

            if send_message:
                await send_message(
                    f"{' '.join(extract_cmd)}",
                    "command",
                    self.tool_type,
                    tool_content,
                    agent=self.agent,
                    tool=self.tool,
                    tool_status=self.tool_status,
                )
                await asyncio.sleep(1)

            result = {
                'status': 'success',
                'binwalk_result_path': str(binwalk_log_file),
                'extracted_files_path': str(actual_extracted_path)
            }
            self._update_status_ini(work_dir, firmware_name, result)
            return result

        except subprocess.TimeoutExpired as e:
            error_msg = f'Binwalk 执行超时(30分钟): {firmware_name}'
            error_result = {
                'status': 'error',
                'message': error_msg
            }
            logger.error(f"Binwalk timeout for {firmware_name}: {str(e)}")
            self._update_status_ini(work_dir, firmware_name, error_result)
            return error_result

        except subprocess.CalledProcessError as e:
            log_excerpt = ''
            try:
                with open(binwalk_log_file, 'r', encoding='utf-8') as log_f:
                    log_excerpt = log_f.read()[-4000:]
            except Exception:
                log_excerpt = e.stderr if hasattr(e, 'stderr') else ''

            error_msg = f'Binwalk 执行失败(返回码 {e.returncode}): {firmware_name}'
            error_result = {
                'status': 'error',
                'message': error_msg,
                'stderr': log_excerpt
            }
            logger.error(f"Binwalk failed for {firmware_name}: returncode={e.returncode}, log={log_excerpt}")
            self._update_status_ini(work_dir, firmware_name, error_result)
            return error_result

        except Exception as e:
            error_msg = f'执行过程中发生未知错误: {type(e).__name__}: {str(e)}'
            error_result = {
                'status': 'error',
                'message': error_msg
            }
            logger.error(f"Binwalk exception for {firmware_name}:")
            logger.error(traceback.format_exc())
            self._update_status_ini(work_dir, firmware_name, error_result)
            return error_result

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

    def get_result(self, task_id: str, firmware_name=None, run_root: str = None) -> dict:
        if not run_root:
            return {
                'status': 'unknown',
                'message': '未提供 run_root，无法定位任务结果'
            }
        base_root = Path(run_root)
        work_dir = base_root / 'binwalk'
        status_file = work_dir / 'status.ini'

        if not os.path.exists(status_file):
            return {
                'status': 'unknown',
                'message': f'未找到任务 {task_id} 的处理结果'
            }

        config = configparser.ConfigParser()
        config.read(status_file)

        if firmware_name is not None:
            if firmware_name in config.sections():
                return {key: value for key, value in config[firmware_name].items()}
            return {
                'status': 'unknown',
                'message': f'未找到固件 {firmware_name} 的处理结果'
            }

        results = {}
        for section in config.sections():
            results[section] = {key: value for key, value in config[section].items()}

        return results
