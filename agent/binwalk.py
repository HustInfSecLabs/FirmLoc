import os
import subprocess
import json
import configparser
import traceback
from pathlib import Path
from typing import Optional
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

    def _task_root_from_config(self, task_id: str, config: ConfigManager) -> Path:
        config_file = Path(config.config_path).expanduser().resolve()
        if config_file.parent.name != task_id:
            raise ValueError(f"配置路径与任务ID不匹配: {config_file}")
        return config_file.parent

    def _binwalk_work_dir(self, task_root: Path) -> Path:
        return task_root / 'binwalk'

    def _is_archive_file(self, filename: str) -> bool:
        normalized = filename.lower()
        return normalized.endswith((
            '.zip',
            '.tar',
            '.rar',
            '.tar.gz',
            '.tgz',
            '.7z',
        ))

    async def process(self, task_id: str, firmware_path: str, config: ConfigManager, send_message=None, on_status_update=None) -> str:
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
        task_root = self._task_root_from_config(task_id, config)
        work_dir = self._binwalk_work_dir(task_root)
        os.makedirs(work_dir, exist_ok=True)

        firmware_dir = work_dir / firmware_name
        os.makedirs(firmware_dir, exist_ok=True)
        extract_path = firmware_dir
        binwalk_log_file = firmware_dir / 'binwalk_result.txt'
        timeout_seconds = 1800
        is_archive_file = self._is_archive_file(firmware_name)
        tool_name = '7z' if is_archive_file else 'binwalk'

        try:
            # 使用绝对路径，避免 cwd 切换后相对路径失效
            if is_archive_file:
                extract_cmd = ['7z', 'x', firmware_path, f'-o{extract_path}', '-y']
            else:
                extract_cmd = ['binwalk', '-Me', firmware_path]

            config.update_tool_status("Online Search", tool_name)
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

            def _run_extract() -> tuple[subprocess.CompletedProcess[str], str, str]:
                with open(binwalk_log_file, 'w', encoding='utf-8') as log_f:
                    result_output = subprocess.run(
                        extract_cmd,
                        stdout=log_f,
                        stderr=subprocess.STDOUT,
                        text=True,
                        check=True,
                        timeout=timeout_seconds,
                        cwd=str(extract_path)
                    )

                    if is_archive_file and firmware_name.lower().endswith(('.tar.gz', '.tgz')):
                        tar_candidates = sorted(extract_path.glob('*.tar'))
                        for tar_file in tar_candidates:
                            subprocess.run(
                                ['7z', 'x', str(tar_file), f'-o{extract_path}', '-y'],
                                stdout=log_f,
                                stderr=subprocess.STDOUT,
                                text=True,
                                check=True,
                                timeout=timeout_seconds,
                                cwd=str(extract_path)
                            )

                if is_archive_file:
                    actual_extracted_path = str(extract_path)
                else:
                    extracted_dirs = sorted(glob.glob(f"{extract_path}/_{firmware_name}*.extracted"), key=os.path.getmtime)
                    if not extracted_dirs:
                        raise RuntimeError("binwalk 未提取出任何目录")
                    actual_extracted_path = extracted_dirs[-1]

                with open(binwalk_log_file, 'r', encoding='utf-8') as log_f:
                    binwalk_output = log_f.read()
                    if len(binwalk_output) > 10240:
                        binwalk_output = "... (输出过长,已截断) ...\n" + binwalk_output[-10240:]

                return result_output, actual_extracted_path, binwalk_output

            result_output, actual_extracted_path, binwalk_output = await asyncio.to_thread(_run_extract)

            if result_output.returncode != 0:
                raise RuntimeError(f"binwalk 执行失败: {result_output.returncode}")

            config.update_tool_status(tool_name)
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
            error_msg = f'{tool_name} 执行超时({timeout_seconds // 60}分钟): {firmware_name}'
            error_result = {
                'status': 'error',
                'message': error_msg
            }
            logger.error(f"{tool_name} timeout for {firmware_name}: {str(e)}")
            self._update_status_ini(work_dir, firmware_name, error_result)
            return error_result

        except subprocess.CalledProcessError as e:
            log_excerpt = ''
            try:
                with open(binwalk_log_file, 'r', encoding='utf-8') as log_f:
                    log_excerpt = log_f.read()[-4000:]
            except Exception:
                log_excerpt = e.stderr if hasattr(e, 'stderr') else ''

            error_msg = f'{tool_name} 执行失败(返回码 {e.returncode}): {firmware_name}'
            error_result = {
                'status': 'error',
                'message': error_msg,
                'stderr': log_excerpt
            }
            logger.error(f"{tool_name} failed for {firmware_name}: returncode={e.returncode}, log={log_excerpt}")
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

        status_config = configparser.ConfigParser()
        if os.path.exists(status_file):
            status_config.read(status_file)

        if status_config.has_section(firmware_name):
            status_config.remove_section(firmware_name)

        status_config.add_section(firmware_name)

        for key, value in result.items():
            status_config.set(firmware_name, key, str(value))

        with open(status_file, 'w') as f:
            status_config.write(f)

    def get_result(self, task_id: str, firmware_name=None, config: Optional[ConfigManager] = None) -> dict:
        if config is None:
            return {
                'status': 'unknown',
                'message': '未提供配置，无法定位任务目录'
            }

        task_root = self._task_root_from_config(task_id, config)
        work_dir = self._binwalk_work_dir(task_root)
        status_file = work_dir / 'status.ini'

        if not os.path.exists(status_file):
            return {
                'status': 'unknown',
                'message': f'未找到任务 {task_id} 的处理结果'
            }

        status_parser = configparser.ConfigParser()
        status_parser.read(status_file)

        if firmware_name is not None:
            if firmware_name in status_parser.sections():
                return {key: value for key, value in status_parser[firmware_name].items()}
            return {
                'status': 'unknown',
                'message': f'未找到固件 {firmware_name} 的处理结果'
            }

        results = {}
        for section in status_parser.sections():
            results[section] = {key: value for key, value in status_parser[section].items()}

        return results

