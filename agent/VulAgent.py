import asyncio
import os
import time
import json
from enum import Enum
from fastapi import WebSocket
from starlette.websockets import WebSocketState
from pathlib import Path
from typing import Optional, Set, List

from model import ChatModel, AgentModel
from agent import UserAgent, PlannerAgent, ida
from agent.parameter_agent import WorkMode, CWE_DESCRIPTIONS
from state import ProgressEnum
from agent.bindiff_agent import BindiffAgent
from agent.ida_toolkits import IdaToolkit
from agent.binwalk import BinwalkAgent
from agent.online_search import OnlineSearchAgent
from agent.llm_diff import main as llm_diff
from agent.path_reach_agent import PathReachAgent, PathReachStatus, RiskLevel
from agent.binary_filter import BinaryFilterAgent
from utils import ConfigManager, PlanManager
from utils.utils import get_firmware_files, copy_file, is_binary_file, get_binary_architecture
from config import config_manager as config
from db import (
    ensure_task,
    get_task_upload_slots,
    mark_task_completed,
    mark_task_failed,
    record_detection_findings,
    record_message,
    record_path_reach_findings,
)
from log import logger


class AnalysisMode(str, Enum):
    AUTO = "auto"
    FIRMWARE = "firmware"
    BINARY_PAIR = "binary_pair"



class VulnAgent:
    def __init__(
        self,
        chat_id: str,
        user_input: str,
        websocket: WebSocket,
        cve_id: Optional[str] = None,
        cwe_id: Optional[str] = None,
        binary_filename: Optional[str] = None,
        vendor: Optional[str] = None,
        work_mode: str = WorkMode.DISCOVERY.value,
        user_model: ChatModel = AgentModel("DeepSeek"),
        planner_model: ChatModel = AgentModel("DeepSeek"),
        config_dir: str = './history',
        analysis_mode: str = AnalysisMode.AUTO.value
    ):
        self.user_model = user_model
        self.planner_model = planner_model
        self.config_dir = config_dir
        self.chat_id = str(chat_id)
        self.user_input = user_input
        self.websocket = websocket
        self._websocket_available = True
        self.cve_id = cve_id
        self.cwe_id = cwe_id
        self.binary_filename = binary_filename
        self.vendor = vendor

        # 工作模式：漏洞复现 or 漏洞挖掘
        self.work_mode = WorkMode(work_mode) if isinstance(work_mode, str) else work_mode

        self.is_last = False
        self.agent = None
        self.tool_status = "stop"
        self.tool = None
        self.command = None
        self.tool_result = None

        self.old_input_path: Optional[str] = None
        self.new_input_path: Optional[str] = None
        self.files = self._load_input_files()
        hint = (analysis_mode or AnalysisMode.AUTO.value).lower()
        if hint not in {mode.value for mode in AnalysisMode}:
            logger.warning("未知分析模式 %s，回退到 auto", hint)
            hint = AnalysisMode.AUTO.value
        self.analysis_mode_hint = hint
        self.resolved_mode: Optional[AnalysisMode] = None

        self._init_bot()

    def _load_input_files(self) -> List[str]:
        task_dir = f"{self.config_dir}/{self.chat_id}"

        # 1) Consult DB upload slots first (authoritative source)
        try:
            slots = get_task_upload_slots(self.chat_id)
            db_old = slots.get("old_input_path")
            db_new = slots.get("new_input_path")
            if db_old and os.path.isfile(db_old):
                self.old_input_path = db_old
            if db_new and os.path.isfile(db_new):
                self.new_input_path = db_new
            if self.old_input_path and self.new_input_path:
                return [self.old_input_path, self.new_input_path]
        except Exception as exc:
            logger.warning("读取 DB 上传槽位失败，回退到目录扫描: %s", exc)

        # 2) Filesystem scan fallback
        task_files = get_firmware_files(task_dir)

        old_candidates = []
        new_candidates = []
        fallback_files = []
        for file_path in task_files:
            name = Path(file_path).name
            if name.startswith("old_"):
                old_candidates.append(file_path)
            elif name.startswith("new_"):
                new_candidates.append(file_path)
            else:
                fallback_files.append(file_path)

        ordered_files: List[str] = []
        if self.old_input_path:
            ordered_files.append(self.old_input_path)
        elif old_candidates:
            self.old_input_path = sorted(old_candidates)[0]
            ordered_files.append(self.old_input_path)

        if self.new_input_path:
            ordered_files.append(self.new_input_path)
        elif new_candidates:
            self.new_input_path = sorted(new_candidates)[0]
            ordered_files.append(self.new_input_path)

        if len(ordered_files) < 2:
            for file_path in sorted(fallback_files):
                if file_path not in ordered_files:
                    ordered_files.append(file_path)
                if len(ordered_files) >= 2:
                    break

        if self.old_input_path is None and ordered_files:
            self.old_input_path = ordered_files[0]
        if self.new_input_path is None and len(ordered_files) >= 2:
            self.new_input_path = ordered_files[1]

        return ordered_files

    def _init_bot(self):
        self.user_agent = UserAgent(self.user_model)
        self.planner_agent = PlannerAgent(self.planner_model)
        self.online_search_agent = OnlineSearchAgent(self.user_model)
        self.BinwalkAgent = BinwalkAgent(self.planner_model)
        self.BinaryFilterAgent = BinaryFilterAgent(self.planner_model)
        self.IDAAgent = IdaToolkit()
        self.BindiffAgent = BindiffAgent(self.chat_id)
        self.PathReachAgent = PathReachAgent()

        self.config_manager = ConfigManager(
            chat_id=self.chat_id,
            user_id=123456,
            user_name="root",
            query=self.user_input,
            upload_files=self.files,
            config_path=self.config_dir
        )
        self.plan_manager = None
        self.tasks = None
        self.results = None
        self.state = ProgressEnum.NOT_STARTED

    def _sync_task_metadata(self) -> None:
        ensure_task(
            chat_id=self.chat_id,
            query=self.user_input,
            cve_id=self.cve_id,
            cwe_id=self.cwe_id,
            binary_filename=self.binary_filename,
            vendor=self.vendor,
            work_mode=self.work_mode.value,
            analysis_mode=self.analysis_mode_hint,
            artifact_dir=os.path.join(self.config_dir, self.chat_id),
            config={
                "uploaded_files": self.files,
                "old_input_path": self.old_input_path,
                "new_input_path": self.new_input_path,
            },
        )

    def _determine_analysis_mode(self) -> AnalysisMode:
        if self.analysis_mode_hint != AnalysisMode.AUTO.value:
            mode = AnalysisMode(self.analysis_mode_hint)
            self.resolved_mode = mode
            return mode

        mode = AnalysisMode.FIRMWARE
        if self.old_input_path and self.new_input_path and all(
            self._looks_like_executable(path) for path in [self.old_input_path, self.new_input_path]
        ):
            mode = AnalysisMode.BINARY_PAIR
        self.resolved_mode = mode
        return mode

    def _looks_like_executable(self, file_path: str) -> bool:
        """Heuristic: only treat as executable when we see a strong executable signature.

        We intentionally bias towards "firmware" for ambiguous raw binaries (e.g. vendor containers like *.w)
        to avoid accidentally skipping Binwalk.
        """
        # 0) Extension-based guard rails (common firmware containers)
        try:
            ext = Path(file_path).suffix.lower()
        except Exception:
            ext = ""
        if ext in {".w", ".trx", ".chk", ".img", ".fw", ".bin"}:
            # Still allow overriding if the file is *clearly* an executable via magic below.
            pass

        try:
            with open(file_path, 'rb') as f:
                header = f.read(1024)
        except OSError:
            return False

        # 1. Known Executables (strong signals)
        if header.startswith(b'\x7fELF'):
            return True
        if header.startswith(b'MZ'):
            return True
        mach_magics = {
            b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe',
            b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe'
        }
        if len(header) >= 4 and header[:4] in mach_magics:
            return True

        # 2. Known Archives/Firmware formats (should go to Binwalk)
        if header.startswith(b"\x1f\x8b"):
            return False  # gzip
        if header.startswith(b"\xFD7zXZ\x00"):
            return False  # xz
        if header.startswith(b"BZh"):
            return False  # bzip2
        if header.startswith(b"PK\x03\x04"):
            return False  # zip
        if len(header) >= 262 and header[257:262] == b"ustar":
            return False  # tar
        if b"hsqs" in header[:64] or b"sqsh" in header[:64]:
            return False  # squashfs
        if header[:6] in {b"070701", b"070702", b"070707"}:
            return False  # cpio

        # 3. Guard rail: treat typical firmware container extensions as firmware by default.
        if ext in {".w", ".trx", ".chk", ".img", ".fw", ".bin"}:
            return False

        # 4. Fallback: unknown binary blobs.
        # Previously we treated any binary as "executable"; that misclassifies firmware containers.
        return False

    def _build_binary_pair_entries(self) -> List[dict]:
        if not self.old_input_path or not self.new_input_path:
            raise ValueError("binary_pair 模式需要显式提供 old/new 两个可执行文件")

        first = self.old_input_path
        second = self.new_input_path
        if not (self._looks_like_executable(first) and self._looks_like_executable(second)):
            raise ValueError("提供的文件不是可执行二进制，无法跳过 Binwalk")
        display_name = self.binary_filename or Path(first).name
        return [{
            "name": display_name,
            "pre": first,
            "post": second,
            "relative_path": Path(first).name,
            "post_relative_path": Path(second).name
        }]

    def _load_cve_details(self, search_result_path: str) -> tuple[str, str]:
        """从搜索结果中加载CVE详情和CWE类型"""
        try:
            with open(search_result_path, 'r', encoding='utf-8') as f:
                content = json.load(f)
            
            vulnerabilities = content.get('vulnerabilities', [])
            if not vulnerabilities:
                logger.warning("搜索结果中没有CVE记录")
                return "", ""
            
            cve = vulnerabilities[0].get('cve', {})
            
            # 获取CVE描述
            descriptions = cve.get('descriptions', [])
            details = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    details = desc.get("value", "")
                    break
            if not details and descriptions:
                details = descriptions[0].get("value", "")
            
            # 获取CWE类型
            cwe = ""
            weaknesses = cve.get('weaknesses', [])
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    if desc.get("value", "").startswith("CWE-"):
                        cwe = desc.get("value")
                        break
                if cwe:
                    break
            
            return details, cwe
        except (FileNotFoundError, KeyError, json.JSONDecodeError, IndexError) as exc:
            logger.warning("解析 CVE 详情失败: %s", exc)
            return "", ""
    
    def _load_discovery_context(self, search_result_path: str) -> dict:
        """从搜索结果中加载漏洞挖掘上下文（历史CVE参考）"""
        try:
            with open(search_result_path, 'r', encoding='utf-8') as f:
                content = json.load(f)
            
            vulnerabilities = content.get('vulnerabilities', [])
            reference_cves = []
            
            for vuln in vulnerabilities[:5]:  # 最多取5个作为参考
                cve = vuln.get('cve', {})
                cve_id = cve.get('id', '')
                
                # 获取描述
                descriptions = cve.get('descriptions', [])
                desc_text = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        desc_text = desc.get("value", "")[:200]
                        break
                
                if cve_id:
                    reference_cves.append({
                        "cve_id": cve_id,
                        "description": desc_text
                    })
            
            return {
                "reference_cves": reference_cves,
                "total_found": content.get('totalResults', 0),
                "search_info": content.get('search_info', {})
            }
        except Exception as exc:
            logger.warning("加载漏洞挖掘上下文失败: %s", exc)
            return {"reference_cves": [], "total_found": 0}
    
    def _get_cwe_description(self, cwe_id: str) -> str:
        """获取CWE类型的描述"""
        if not cwe_id:
            return ""
        return CWE_DESCRIPTIONS.get(cwe_id.upper(), f"Vulnerability type: {cwe_id}")

    def _can_send_websocket(self) -> bool:
        return self._websocket_available and self.websocket.client_state == WebSocketState.CONNECTED

    def on_status_update(self, command=None, tool=None, tool_status=None):
        if command is not None:
            self.command = command
        if tool is not None:
            self.tool = tool
        if tool_status is not None:
            self.tool_status = tool_status
            if self.config_manager:
                if tool_status in {"completed", "stop"}:
                    self.config_manager.update_tool_status(completed_tool=tool)
                elif tool:
                    self.config_manager.update_tool_status(new_running_tool=tool)

    async def send_message(self, content: str, message_type="message", tool_type=None, tool_content=None, agent=None, tool=None, tool_status=None):
        """
        发送消息到 WebSocket
        """
        system_status = {
            "status": self.state.name,
            "agent": agent,
            "tool": tool
        }

        if tool:
            tool_status = {
                "type": tool_type,
                "title": tool_status,
                "content": tool_content
            }

        response = {
            "chat_id": self.chat_id,
            "is_last": self.is_last,
            "type": message_type,
            "content": content,
            "system_status": system_status,
            "tool_status": tool_status
        }

        try:
            record_message(
                chat_id=self.chat_id,
                content=content,
                message_type=message_type,
                agent=agent,
                tool=tool,
                tool_status=tool_status,
                is_last=self.is_last,
            )
        except Exception as exc:
            logger.warning("记录消息事件失败: %s", exc)

        if not self._can_send_websocket():
            return

        try:
            await self.websocket.send_json(response)
            logger.info(f"发送消息: {response}")
        except Exception as e:
            self._websocket_available = False
            logger.info(f"WebSocket 已关闭，跳过发送消息: {str(e)}")

    async def chat(self):
        self._sync_task_metadata()
        if self.work_mode == WorkMode.REPRODUCTION:
            # 漏洞复现模式：需要CVE ID
            if not self.cve_id or not self.binary_filename:
                error_msg = "漏洞复现模式需要提供CVE编号和目标二进制文件名称。"
                await self.send_message(error_msg, message_type="message")
                logger.error(error_msg)
                mark_task_failed(self.chat_id, error_msg)
                return error_msg
        else:
            # 漏洞挖掘模式：需要CWE ID
            if not self.cwe_id or not self.binary_filename:
                error_msg = "漏洞挖掘模式需要提供CWE类型和目标二进制文件名称。"
                await self.send_message(error_msg, message_type="message")
                logger.error(error_msg)
                mark_task_failed(self.chat_id, error_msg)
                return error_msg

        resolved_mode = self._determine_analysis_mode()
        files = self.files

        if resolved_mode == AnalysisMode.FIRMWARE and (not self.old_input_path or not self.new_input_path):
            error_msg = "固件模式需要显式上传 old/new 两个固件镜像。"
            await self.send_message(error_msg, message_type="message")
            logger.error(error_msg)
            mark_task_failed(self.chat_id, error_msg)
            return error_msg

        def show_file_info(full_path: str):
            """给定文件路径打印大小，便于排查。"""
            if not os.path.isfile(full_path):
                print(f"[错误] 文件不存在：{full_path}")
                return
            size_bytes = os.path.getsize(full_path)
            print(f"文件路径：{full_path}")
            print(f"文件大小：{size_bytes} 字节")

        if resolved_mode == AnalysisMode.FIRMWARE:
            self.tasks = """
## 1.使用Binwalk提取固件文件
## 2.筛选出可能存在漏洞的二进制文件
## 3.使用IDA导出两个不同版本二进制文件的.Binexport文件
## 4.使用BinDiff分析两个.export文件的差异
## 5.分析BinDiff的结果，找出可能存在漏洞的函数
## 6.使用IDA导出函数的伪C代码
## 7.使用Detection Agent分析函数的伪C代码
            """
        else:
            self.tasks = """
## 1.校验用户上传的二进制/Windows 程序对，无需解包
## 2.直接为两个版本生成IDA BinExport文件
## 3.使用BinDiff分析两个版本差异
## 4.Detection Agent 分析伪C代码并输出漏洞研判报告
            """
        logger.info("Tasks: %s", self.tasks)

        self.plan_manager = PlanManager(
            chat_id=self.chat_id,
            plan_path=self.config_dir,
            query=self.user_input,
            upload_files=self.files,
            plan=self.tasks
        )

        self.config_manager.update_agent_status(new_running_agent="Intelligence Agent")
        self.agent = "Intelligence Agent"
        self.tool = None
        self.state = ProgressEnum.RUNNING

        # 根据工作模式执行不同的情报收集策略
        cve_details = ""
        cwe = self.cwe_id or ""
        reference_cves = None
        discovery_context = {}

        if self.work_mode == WorkMode.REPRODUCTION:
            # 漏洞复现模式：搜索特定CVE
            await self.send_message("情报收集智能体收集CVE相关信息",
                                     message_type="header1",
                                     agent=self.agent)
            search_result = await asyncio.to_thread(
                self.online_search_agent.process,
                task_id=self.chat_id,
                cve_id=self.cve_id,
                work_mode="reproduction",
            )
            logger.info("Online search result: %s", search_result)

            if search_result.get('status') == 'success':
                with open(search_result['search_result_path'], 'r', encoding='utf-8') as f:
                    tool_content = [{"type": "text", "content": f.read()}]
                    await self.send_message("调用在线搜索API访问https://services.nvd.nist.gov",
                                            message_type="command",
                                            tool_type="graphics",
                                            tool_content=tool_content,
                                            agent=self.agent,
                                            tool="Online Search",
                                            tool_status="running")
                cve_details, cwe = self._load_cve_details(search_result['search_result_path'])
        else:
            # 漏洞挖掘模式：搜索历史同类型CVE作为参考
            cwe_desc = self._get_cwe_description(self.cwe_id)
            await self.send_message(f"情报收集智能体搜索历史{self.cwe_id}类型CVE作为参考\n类型描述: {cwe_desc}",
                                     message_type="header1",
                                     agent=self.agent)
            search_result = await asyncio.to_thread(
                self.online_search_agent.process,
                task_id=self.chat_id,
                cwe_id=self.cwe_id,
                vendor=self.vendor,
                model=self.binary_filename,
                work_mode="discovery",
            )
            logger.info("Online search result (discovery mode): %s", search_result)

            if search_result.get('status') == 'success':
                with open(search_result['search_result_path'], 'r', encoding='utf-8') as f:
                    content = f.read()
                    tool_content = [{"type": "text", "content": content}]
                    await self.send_message(
                        f"搜索到 {search_result.get('total_cves', 0)} 个相关历史CVE作为参考",
                        message_type="command",
                        tool_type="graphics",
                        tool_content=tool_content,
                        agent=self.agent,
                        tool="Online Search",
                        tool_status="running"
                    )
                discovery_context = self._load_discovery_context(search_result['search_result_path'])
                reference_cves = content
                # 使用CWE描述作为cve_details的替代
                cve_details = f"{self.cwe_id}: {cwe_desc}"
                cwe = self.cwe_id
            else:
                # 搜索失败也继续，使用CWE描述
                cve_details = f"{self.cwe_id}: {cwe_desc}"
                cwe = self.cwe_id
                await self.send_message(
                    f"历史CVE搜索未找到结果，将使用CWE类型特征进行漏洞挖掘",
                    message_type="message",
                    agent=self.agent
                )

        analysis_pairs: List[dict] = []

        if resolved_mode == AnalysisMode.FIRMWARE:
            self.config_manager.update_agent_status("Intelligence Agent", "Binwalk Agent")
            self.agent = "Binwalk Agent"
            await self.send_message("Binwalk Agent提取固件文件",
                                    message_type="header1",
                                    agent=self.agent)
            binwalk_results = []
            for file in files:
                binwalk_result = await self.BinwalkAgent.process(
                    task_id=self.chat_id,
                    firmware_path=str(file),
                    config=self.config_manager,
                    send_message=self.send_message,
                    on_status_update=self.on_status_update)
                logger.info("Binwalk result: %s", binwalk_result)
                binwalk_results.append(binwalk_result)

            failed_results = [r for r in binwalk_results if r.get('status') == 'error']
            if failed_results:
                error_msg = f"固件提取失败: {'; '.join([r.get('message', '未知错误') for r in failed_results])}"
                await self.send_message(error_msg, message_type="message", agent=self.agent)
                logger.error(error_msg)
                mark_task_failed(self.chat_id, error_msg)
                return error_msg

            self.config_manager.update_agent_status("Binwalk Agent", "Binary Filter Agent")
            self.config_manager.update_tool_status("Binwalk", "Binary Filter")
            self.agent = "Binary Filter Agent"

            # 根据工作模式显示不同的提示信息
            if self.work_mode == WorkMode.DISCOVERY:
                await self.send_message(f"Binary Filter Agent基于{self.cwe_id}特征筛选可疑文件",
                                         message_type="header1",
                                         agent=self.agent)
            else:
                await self.send_message("Binary Filter Agent筛选可疑文件列表",
                                         message_type="header1",
                                         agent=self.agent)

            llm_result = await asyncio.to_thread(
                self.BinaryFilterAgent.process,
                binary_filename=self.binary_filename,
                extracted_files_path=binwalk_results[0]['extracted_files_path'],
                cve_details=cve_details,
                cwe_id=self.cwe_id if self.work_mode == WorkMode.DISCOVERY else None,
                work_mode=self.work_mode.value,
                reference_cves=reference_cves,
                old_firmware_path=binwalk_results[0]['extracted_files_path'],
                new_firmware_path=binwalk_results[1]['extracted_files_path'],
                enable_diff_filter=True,
            )
            logger.info("BinaryFilter result: %s", llm_result)

            if llm_result.get("diff_statistics"):
                stats = llm_result["diff_statistics"]
                diff_msg = (
                    f"二进制差异统计: 修改={stats['modified_count']}, 新增={stats['added_count']}, "
                    f"删除={stats['removed_count']}, 未变化={stats['unchanged_count']}"
                )
                await self.send_message(diff_msg, message_type="message", agent=self.agent)
                logger.info(diff_msg)

            if llm_result.get("status") != "success" or not llm_result.get("suspicious_binaries"):
                error_msg = llm_result.get("message", "BinaryFilter 未返回可疑二进制")
                await self.send_message(error_msg, message_type="message", agent=self.agent)
                logger.error(error_msg)
                mark_task_failed(self.chat_id, error_msg)
                return error_msg

            suspicious_files = [os.path.join(item['binary_path']) for item in llm_result["suspicious_binaries"]]
            formatted_lines = [f"{i+1}. {path}" for i, path in enumerate(suspicious_files)]
            await self.send_message("可疑文件:\n" + '\n'.join(formatted_lines),
                                    message_type="message",
                                    agent=self.agent)

            for entry in llm_result["suspicious_binaries"]:
                relative_path = entry.get("binary_path", "").strip() or entry.get("binary_name", "").strip()
                if not relative_path:
                    continue
                relative_path = os.path.normpath(relative_path.lstrip("./"))
                file1 = os.path.join(binwalk_results[0]['extracted_files_path'], relative_path)
                file2 = os.path.join(binwalk_results[1]['extracted_files_path'], relative_path)
                analysis_pairs.append({
                    "name": entry.get("binary_name", Path(relative_path).name),
                    "pre": file1,
                    "post": file2,
                    "relative_path": relative_path
                })

            if not analysis_pairs:
                error_msg = "Binary Filter 未能提供有效的二进制路径。"
                await self.send_message(error_msg, message_type="message", agent=self.agent)
                logger.error(error_msg)
                mark_task_failed(self.chat_id, error_msg)
                return error_msg

        else:
            self.config_manager.update_agent_status("Intelligence Agent", "Binwalk Agent")
            self.agent = "Binwalk Agent"
            await self.send_message("检测到可执行程序输入，自动跳过 Binwalk 解包阶段。",
                                    message_type="header1",
                                    agent=self.agent)
            self.config_manager.update_agent_status("Binwalk Agent", "Binary Filter Agent")
            self.config_manager.update_tool_status("Binwalk", "Binary Filter")
            self.agent = "Binary Filter Agent"
            await self.send_message("Binary Filter Agent 直接使用用户提供的二进制对。",
                                    message_type="header1",
                                    agent=self.agent)
            try:
                analysis_pairs = self._build_binary_pair_entries()
            except ValueError as exc:
                mark_task_failed(self.chat_id, str(exc))
                await self.send_message(str(exc), message_type="message", agent=self.agent)
                logger.error(str(exc))
                return str(exc)

            summary_lines = [
                f"{idx+1}. {Path(pair['pre']).name} ↔ {Path(pair['post']).name}"
                for idx, pair in enumerate(analysis_pairs)
            ]
            await self.send_message("二进制对列表:\n" + '\n'.join(summary_lines),
                                    message_type="message",
                                    agent=self.agent)

        self.config_manager.update_agent_status("Binary Filter Agent", "IDA Agent")
        self.config_manager.update_tool_status("Binary Filter", "IDA Decompiler")

        idadir = os.path.join(self.config_dir, self.chat_id, "ida")
        bindiffdir = os.path.join(self.config_dir, self.chat_id, "bindiff")
        if not analysis_pairs:
            error_msg = "未找到可用于后续分析的二进制文件。"
            await self.send_message(error_msg, message_type="message")
            mark_task_failed(self.chat_id, error_msg)
            return error_msg

        for pair in analysis_pairs:
            file1 = pair["pre"]
            file2 = pair["post"]
            display_name = pair.get("name", Path(file1).name)
            if not os.path.isfile(file1):
                print(f"文件不存在: {file1}")
                continue
            if not os.path.isfile(file2):
                print(f"文件不存在: {file2}")
                continue
            if not is_binary_file(file1) or not is_binary_file(file2):
                await self.send_message(f"文件 {file1} 不是二进制文件，跳过分析。",
                                        message_type="header2",
                                        agent=self.agent)
                continue

            os.makedirs(idadir, exist_ok=True)
            output_path1 = os.path.join(idadir, f"{os.path.basename(file1)}")
            output_path2 = os.path.join(idadir, f"{os.path.basename(file2)}1")
            show_file_info(file1)
            show_file_info(file2)
            file2 = copy_file(file2, os.path.dirname(file2))

            self.tool = "IDA Decompiler"
            self.tool_status = "running"
            self.agent = "IDA Agent"
            await self.send_message(f"IDA Agent分析二进制文件{display_name}",
                                    message_type="header1",
                                    agent=self.agent)

            ida_service_url = config.config["IDA_SERVICE"]["service_url"]
            ida_version_file1 = get_binary_architecture(file1)
            ida_version_file2 = get_binary_architecture(file2)
            logger.info("文件1 (%s) 使用 IDA 版本: %s", file1, ida_version_file1)
            logger.info("文件2 (%s) 使用 IDA 版本: %s", file2, ida_version_file2)

            await ida.ida_process(input_file_path=file1, output_dir=output_path1, ida_service_url=ida_service_url, ida_version=ida_version_file1, config=self.config_manager, send_message=self.send_message, on_status_update=self.on_status_update)
            await ida.ida_process(input_file_path=file2, output_dir=output_path2, ida_service_url=ida_service_url, ida_version=ida_version_file2, config=self.config_manager, send_message=self.send_message, on_status_update=self.on_status_update)
            output_file1 = os.path.join("test", f"{os.path.basename(file1)}.BinExport")
            output_file2 = os.path.join("test", f"{os.path.basename(file2)}.BinExport")
            output_dir = os.path.join(bindiffdir, f"{os.path.basename(file1)}")

            self.config_manager.update_agent_status("IDA Agent", "Bindiff Agent")
            self.config_manager.update_tool_status("IDA Decompiler", "Bindiff")
            self.tool = "Bindiff"
            self.tool_status = "running"
            self.agent = "Bindiff Agent"
            await self.send_message("Bindiff Agent对比两个二进制文件",
                                    message_type="header1",
                                    agent=self.agent)

            bindiff_result = await self.BindiffAgent.execute(output_file1, output_file2, output_dir, self.config_manager, send_message=self.send_message, on_status_update=self.on_status_update)
            logger.info("Bindiff result: %s", bindiff_result)

            self.agent = "Detection Agent"
            self.tool = None
            self.config_manager.update_agent_status("Bindiff Agent", "Detection Agent")
            await self.send_message("Detection Agent分析Bindiff结果",
                                    message_type="header1",
                                    agent=self.agent)
            await llm_diff(
                chat_id=self.chat_id,
                history_root=self.config_dir,
                pre_c=os.path.join(output_path1, f"{os.path.basename(file1)}_pseudo.c"),
                post_c=os.path.join(output_path2, f"{os.path.basename(file2)}_pseudo.c"),
                binary_filename=os.path.basename(file1),
                post_binary_filename=os.path.basename(file2),
                cve_details=cve_details,
                cwe=cwe,
                send_message=self.send_message,
                work_mode=self.work_mode.value
            )

            vulnerable_functions = await self._extract_vulnerable_functions_from_llm_diff(
                chat_id=self.chat_id,
                history_root=self.config_dir,
                binary_name=os.path.basename(file1)
            )
            record_detection_findings(
                chat_id=self.chat_id,
                binary_name=os.path.basename(file1),
                vulnerable_functions=vulnerable_functions,
                cwe_id=cwe,
                related_cve=self.cve_id,
            )

            if vulnerable_functions:
                self.agent = "Path Reach Agent"
                self.tool = None
                self.config_manager.update_agent_status("Detection Agent", "Path Reach Agent")
                await self.send_message(
                    f"Path Reach Agent 分析 {len(vulnerable_functions)} 个漏洞函数的路径可达性",
                    message_type="header1",
                    agent=self.agent
                )

                try:
                    absolute_binary_path = os.path.abspath(file1)
                    reach_results = await self.PathReachAgent.analyze_reachability(
                        binary_path=absolute_binary_path,
                        vulnerable_functions=vulnerable_functions,
                        cwe_type=cwe,
                        send_message=self.send_message
                    )

                    reach_summary = self.PathReachAgent.format_results_for_display(reach_results)
                    await self.send_message(
                        reach_summary,
                        message_type="message",
                        agent=self.agent
                    )

                    reach_output_path = os.path.join(
                        self.config_dir, self.chat_id, "path_reach_results.json"
                    )
                    self.PathReachAgent.save_results(reach_results, reach_output_path)
                    record_path_reach_findings(
                        chat_id=self.chat_id,
                        binary_name=os.path.basename(file1),
                        results=reach_results,
                        cwe_id=cwe,
                        related_cve=self.cve_id,
                    )

                except Exception as e:
                    logger.error(f"路径可达性分析失败: {e}", exc_info=True)
                    await self.send_message(
                        f"路径可达性分析失败: {str(e)}",
                        message_type="message",
                        agent=self.agent
                    )
            else:
                logger.info("Detection Agent 未认定漏洞函数，跳过路径可达性分析")

        self.is_last = True
        self.state = ProgressEnum.COMPLETED
        response = ""
        self.agent = None
        self.tool = None
        self.config_manager.update_agent_status(new_running_agent=None)
        self.config_manager.update_tool_status(new_running_tool=None)
        await self.send_message("系统运行完成。感谢使用 VulnAgent！",
                                 message_type="message")
        mark_task_completed(self.chat_id)
        logger.info("系统运行完成")

        return response

    async def _extract_vulnerable_functions_from_llm_diff(
        self,
        chat_id: str,
        history_root: str,
        binary_name: Optional[str] = None
    ) -> List[str]:
        """
        从 Detection Agent (llm_diff) 的结果中提取认定的漏洞函数

        Args:
            chat_id: 会话 ID
            history_root: 历史记录根目录
            binary_name: 当前分析的二进制文件名（不含路径），用于限制扫描范围，
                         避免把其他二进制的分析结果混入。为 None 时扫描所有目录（不推荐）。

        Returns:
            认定存在漏洞的函数名列表
        """
        import re
        import glob

        vulnerable_funcs = []
        results_dir = os.path.join(history_root, chat_id)

        # 查找 bindiff 目录下的 vuln_analysis_results.json 文件
        # 路径格式: {history_root}/{chat_id}/bindiff/{binary_name}/diff_*/vuln_analysis_results.json
        bindiff_dir = os.path.join(results_dir, "bindiff")
        if os.path.isdir(bindiff_dir):
            if binary_name:
                # 只扫描当前二进制对应的子目录，避免跨二进制污染
                pattern = os.path.join(bindiff_dir, binary_name, "diff_*", "vuln_analysis_results.json")
            else:
                # 兜底：扫描所有子目录（历史兼容，不推荐）
                logger.warning("_extract_vulnerable_functions_from_llm_diff: binary_name 未指定，将扫描所有二进制的结果，可能导致函数列表跨二进制污染！")
                pattern = os.path.join(bindiff_dir, "*", "diff_*", "vuln_analysis_results.json")
            logger.info(f"[扫描漏洞函数] binary_name={binary_name}, pattern={pattern}")
            result_files = glob.glob(pattern)
            logger.info(f"[扫描漏洞函数] 找到 {len(result_files)} 个结果文件: {result_files}")

            for result_file in result_files:
                try:
                    with open(result_file, "r", encoding="utf-8") as f:
                        content = f.read()

                    # 解析特殊格式: === function_name.c vs function_name.c === 后跟 JSON 块
                    vulnerable_funcs.extend(self._parse_llm_diff_format(content))

                except Exception as e:
                    logger.warning(f"解析结果文件失败 {result_file}: {e}")
                    continue

        # 去重
        vulnerable_funcs = list(set(vulnerable_funcs))
        logger.info(f"从 Detection Agent 结果中提取到 {len(vulnerable_funcs)} 个漏洞函数: {vulnerable_funcs}")

        return vulnerable_funcs

    def _parse_llm_diff_format(self, content: str) -> List[str]:
        """
        解析 LLM Diff 特殊格式的分析结果（优先使用 ReAct 分析结果）

        格式示例:
        === uh_cgi_auth_check.c vs uh_cgi_auth_check.c ===
        {初次分析结果}

        === uh_cgi_auth_check.c vs uh_cgi_auth_check.c (ReAct分析) ===
        {ReAct 二次分析结果}

        逻辑:
        1. 优先使用 ReAct 分析结果 (检查 vulnerability_found 字段)
        2. 如果 ReAct 结果为 unknown，回退到初次分析结果
        3. 如果没有 ReAct 结果，使用初次分析结果

        Args:
            content: 文件内容

        Returns:
            认定存在漏洞的函数名列表
        """
        import re
        vulnerable_funcs = []

        # 先收集所有函数的初次分析结果
        initial_results = {}  # {func_name: is_vulnerable}

        sections = re.split(r'===\s+(\w+)\.c\s+vs\s+\w+\.c\s+===', content)
        for i in range(1, len(sections), 2):
            if i + 1 >= len(sections):
                break

            func_name = sections[i]
            section_content = sections[i + 1]

            # 只提取初次分析部分（截取到下一个=== 或 (ReAct分析) 之前）
            # 如果section_content包含下一个函数的分析，先截断
            next_section_match = re.search(r'\n===\s+\w+\.c\s+vs\s+\w+\.c', section_content)
            if next_section_match:
                section_content = section_content[:next_section_match.start()]

            # 移除 markdown 代码块标记
            cleaned_content = re.sub(r'```json\s*', '', section_content)
            cleaned_content = re.sub(r'```\s*', '', cleaned_content)

            # 尝试提取 JSON 对象
            json_match = re.search(r'\{[\s\S]*?\}', cleaned_content)
            if not json_match:
                continue

            try:
                data = json.loads(json_match.group(0))
                initial_results[func_name] = self._is_vulnerability_confirmed_in_dict(data)
            except json.JSONDecodeError:
                continue

        # 再查找 ReAct 分析结果
        react_pattern = r'===\s+(\w+)\.c\s+vs\s+\w+\.c\s+\(ReAct分析\)\s+===\s*([\s\S]*?)(?=\n===|\Z)'
        react_matches = re.finditer(react_pattern, content, re.MULTILINE)

        react_analyzed_funcs = set()
        for match in react_matches:
            func_name = match.group(1)
            react_content = match.group(2)

            # 移除 markdown 代码块标记
            react_content = re.sub(r'```json\s*', '', react_content)
            react_content = re.sub(r'```\s*', '', react_content)

            # 尝试提取 JSON 对象
            json_match = re.search(r'\{[\s\S]*\}', react_content)
            if not json_match:
                logger.warning(f"未找到 JSON (ReAct 函数: {func_name})")
                continue

            try:
                data = json.loads(json_match.group(0))
                vuln_found = data.get("vulnerability_found", "").strip().lower()

                react_analyzed_funcs.add(func_name)

                if vuln_found == "yes":
                    # ReAct 明确认定为漏洞
                    vulnerable_funcs.append(func_name)
                    logger.info(f"[ReAct 分析] 发现漏洞函数: {func_name}")
                elif vuln_found == "no":
                    # ReAct 明确认定非漏洞，覆盖初次分析
                    logger.info(f"[ReAct 分析] 函数 {func_name} 非漏洞 (覆盖初次分析)")
                else:
                    # ReAct 未明确判断 (unknown/parse_error)，回退到初次分析
                    if initial_results.get(func_name, False):
                        vulnerable_funcs.append(func_name)
                        logger.info(f"[回退初次分析] 发现漏洞函数: {func_name} (ReAct 结果 unknown)")
                    else:
                        logger.info(f"[回退初次分析] 函数 {func_name} 非漏洞")

            except json.JSONDecodeError as e:
                logger.warning(f"解析 ReAct JSON 失败 (函数: {func_name}): {e}")
                # 解析失败，回退到初次分析
                if initial_results.get(func_name, False):
                    vulnerable_funcs.append(func_name)
                    logger.info(f"[回退初次分析] 发现漏洞函数: {func_name} (ReAct 解析失败)")

        # 对于没有 ReAct 分析的函数，使用初次分析结果
        for func_name, is_vulnerable in initial_results.items():
            if func_name not in react_analyzed_funcs and is_vulnerable:
                vulnerable_funcs.append(func_name)
                logger.info(f"[初次分析] 发现漏洞函数: {func_name} (无 ReAct 分析)")

        return vulnerable_funcs

    def _parse_json_results(self, data: dict) -> List[str]:
        """解析 JSON 格式的分析结果"""
        vulnerable_funcs = []

        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    vulnerable_funcs.extend(self._extract_vuln_from_item(item))
        elif isinstance(data, dict):
            # 可能是按函数名组织的结果
            for func_name, result in data.items():
                if isinstance(result, dict):
                    if self._is_vulnerability_confirmed_in_dict(result):
                        vulnerable_funcs.append(func_name)

        return vulnerable_funcs

    def _extract_vuln_from_item(self, item: dict) -> List[str]:
        """从单个结果项中提取漏洞函数"""
        funcs = []

        # 检查是否确认漏洞
        if not self._is_vulnerability_confirmed_in_dict(item):
            return funcs

        # 提取函数名
        for key in ["function_name", "func_name", "function", "name", "vulnerable_function"]:
            if key in item and item[key]:
                funcs.append(str(item[key]))
                break

        return funcs

    def _is_vulnerability_confirmed_in_dict(self, result: dict) -> bool:
        """检查 dict 结果是否确认存在漏洞"""
        # 检查各种可能的确认字段
        confirm_fields = [
            ("vulnerability_found", ["yes", "true", "1"]),
            ("is_vulnerable", ["yes", "true", "1", True]),
            ("scenario_match", ["yes", "true", "1"]),
            ("property_match", ["yes", "true", "1"]),
            ("Scenario_match & Property_match", ["yes", "true", "1"]),
        ]

        for field, positive_values in confirm_fields:
            if field in result:
                value = result[field]
                if isinstance(value, bool) and value:
                    return True
                if isinstance(value, str) and value.lower() in [str(v).lower() for v in positive_values]:
                    return True

        # 检查组合条件
        scenario = str(result.get("scenario_match", "")).lower()
        property_match = str(result.get("property_match", "")).lower()
        if scenario == "yes" and property_match == "yes":
            return True

        return False

    def _parse_text_results(self, content: str) -> List[str]:
        """解析文本/markdown 格式的分析结果"""
        import re
        vulnerable_funcs = []

        # 尝试从文本中提取 JSON 块
        json_pattern = r'\{[^{}]*"(?:vulnerability_found|scenario_match|is_vulnerable)"[^{}]*\}'
        json_matches = re.findall(json_pattern, content, re.DOTALL | re.IGNORECASE)

        for match in json_matches:
            try:
                data = json.loads(match)
                if self._is_vulnerability_confirmed_in_dict(data):
                    # 尝试从上下文中提取函数名
                    func_name = self._extract_func_name_from_context(content, match)
                    if func_name:
                        vulnerable_funcs.append(func_name)
            except json.JSONDecodeError:
                continue

        # 正则匹配常见的漏洞确认模式
        patterns = [
            r'===\s+(\w+)\.c\s+.*?===.*?(?:vulnerability_found|scenario_match).*?["\']?yes["\']?',
            r'函数\s*[：:]\s*(\w+).*?存在漏洞',
            r'(\w+)\s+(?:is|has)\s+(?:vulnerable|vulnerability)',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                if match and len(match) > 2:
                    vulnerable_funcs.append(match)

        return vulnerable_funcs

    def _extract_func_name_from_context(self, content: str, json_match: str) -> Optional[str]:
        """从上下文中提取函数名"""
        import re

        # 查找 json_match 在 content 中的位置
        pos = content.find(json_match)
        if pos == -1:
            return None

        # 在 json_match 之前的内容中查找函数名
        before_content = content[max(0, pos - 500):pos]

        # 匹配 "=== xxx.c vs yyy.c ===" 格式
        func_pattern = r'===\s+(\w+)\.c\s+'
        matches = re.findall(func_pattern, before_content)
        if matches:
            return matches[-1]  # 返回最近的匹配

        # 匹配 "Function: xxx" 格式
        func_pattern2 = r'[Ff]unction[:\s]+(\w+)'
        matches2 = re.findall(func_pattern2, before_content)
        if matches2:
            return matches2[-1]

        return None

