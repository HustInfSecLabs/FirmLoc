import asyncio
import os
import time
import json
import asyncio
from enum import Enum
from fastapi import WebSocket
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
from agent.binary_filter import BinaryFilterAgent
from log import logger
from utils import ConfigManager, PlanManager
from utils.utils import get_firmware_files, copy_file, is_binary_file, get_binary_architecture
from config import config_manager as config


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

        self.files = get_firmware_files(f"{self.config_dir}/{self.chat_id}")
        hint = (analysis_mode or AnalysisMode.AUTO.value).lower()
        if hint not in {mode.value for mode in AnalysisMode}:
            logger.warning("未知分析模式 %s，回退到 auto", hint)
            hint = AnalysisMode.AUTO.value
        self.analysis_mode_hint = hint
        self.resolved_mode: Optional[AnalysisMode] = None

        self._init_bot()

    def _init_bot(self):
        self.user_agent = UserAgent(self.user_model)
        self.planner_agent = PlannerAgent(self.planner_model)
        self.online_search_agent = OnlineSearchAgent(self.user_model)
        self.BinwalkAgent = BinwalkAgent(self.planner_model)
        self.BinaryFilterAgent = BinaryFilterAgent(self.planner_model)
        self.IDAAgent = IdaToolkit()
        self.BindiffAgent = BindiffAgent(self.chat_id)
        
        self.config_manager = ConfigManager(
            chat_id=self.chat_id,
            user_id=123456,
            user_name="root",
            query=self.user_input,
            upload_files=self.files,
            config_path=self.config_dir
        )
        self.plan_manager = None
        #self.chat_id = None
        self.tasks = None
        self.results = None
        self.state = ProgressEnum.NOT_STARTED
    

    def _determine_analysis_mode(self) -> AnalysisMode:
        if self.analysis_mode_hint != AnalysisMode.AUTO.value:
            mode = AnalysisMode(self.analysis_mode_hint)
            self.resolved_mode = mode
            return mode

        mode = AnalysisMode.FIRMWARE
        if len(self.files) == 2 and all(self._looks_like_executable(path) for path in self.files):
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
        binaries = sorted(self.files)
        if len(binaries) < 2:
            raise ValueError("binary_pair 模式需要至少两个可执行文件")
        first, second = binaries[:2]
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

    def on_status_update(self, command=None, tool=None, tool_status=None, tool_result=None):
        if command is not None:
            self.command = command
        if tool is not None:
            self.tool = tool
        if tool_status is not None:
            self.tool_status = tool_status
        if tool_result is not None:
            self.tool_result = tool_result

    async def send_message(self, content: str, message_type="message", tool_type=None, tool_content=None, agent=None, tool=None, tool_status=None):
        """
        发送消息到 WebSocket
        """
        system_status = {
            "status": self.state.name,
            "agent": agent,
            "tool": tool
        }

        # tool_status = None
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
            await self.websocket.send_json(response)
            logger.info(f"发送消息: {response}")
        except Exception as e:
            logger.error(f"发送消息失败: {str(e)}")

    async def chat(self):
        """
        聊天接口
        :param chat_id: 会话ID
        :param query: 用户查询内容
        :return: 聊天响应
        """
        
        # 根据工作模式检查必要参数
        if self.work_mode == WorkMode.REPRODUCTION:
            # 漏洞复现模式：需要CVE ID
            if not self.cve_id or not self.binary_filename:
                error_msg = "漏洞复现模式需要提供CVE编号和目标二进制文件名称。"
                await self.send_message(error_msg, message_type="message")
                logger.error(error_msg)
                return error_msg
        else:
            # 漏洞挖掘模式：需要CWE ID
            if not self.cwe_id or not self.binary_filename:
                error_msg = "漏洞挖掘模式需要提供CWE类型和目标二进制文件名称。"
                await self.send_message(error_msg, message_type="message")
                logger.error(error_msg)
                return error_msg

        resolved_mode = self._determine_analysis_mode()
        files = self.files

        if resolved_mode == AnalysisMode.FIRMWARE and len(files) != 2:
            error_msg = "固件模式需要上传两个固件镜像。"
            await self.send_message(error_msg, message_type="message")
            logger.error(error_msg)
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
            search_result = self.online_search_agent.process(
                task_id=self.chat_id, 
                cve_id=self.cve_id,
                work_mode="reproduction"
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
            search_result = self.online_search_agent.process(
                task_id=self.chat_id,
                cwe_id=self.cwe_id,
                vendor=self.vendor,
                model=self.binary_filename,
                work_mode="discovery"
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

            # 调用 BinaryFilterAgent，传入工作模式和相关参数
            llm_result = self.BinaryFilterAgent.process(
                binary_filename=self.binary_filename,
                extracted_files_path=binwalk_results[0]['extracted_files_path'],
                cve_details=cve_details,
                cwe_id=self.cwe_id if self.work_mode == WorkMode.DISCOVERY else None,
                work_mode=self.work_mode.value,
                reference_cves=reference_cves
            )
            logger.info("BinaryFilter result: %s", llm_result)

            if llm_result.get("status") != "success" or not llm_result.get("suspicious_binaries"):
                error_msg = llm_result.get("message", "BinaryFilter 未返回可疑二进制")
                await self.send_message(error_msg, message_type="message", agent=self.agent)
                logger.error(error_msg)
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
            logger.error(error_msg)
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
                work_mode=self.work_mode.value  # 传递工作模式
            )

        self.is_last = True
        self.state = ProgressEnum.COMPLETED
        response = ""
        self.agent = None
        self.tool = None
        self.config_manager.update_agent_status(new_running_agent=None)
        self.config_manager.update_tool_status(new_running_tool=None)
        await self.send_message("系统运行完成。感谢使用 VulnAgent！",
                                 message_type="message")
        logger.info("系统运行完成")

        return response

