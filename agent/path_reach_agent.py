"""
PathReachAgent - 路径可达性分析智能体

在 Detection Agent 认定漏洞后，调用 DeepauditExtension 集成的 zero_day 路径分析端点验证路径可达性和可利用性。

工作流程：
1. 接收 Detection Agent 认定的漏洞函数列表
2. 调用 DeepauditExtension 的 /api/v1/zero-day-agent/path-reachable 接口
3. 解析返回结果，按风险等级分类
4. 格式化结果用于展示
"""
import os
import json
import asyncio
import aiohttp
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum

from log import logger
from config import config_manager


class PathReachStatus(str, Enum):
    """路径可达状态"""
    REACHABLE = "reachable"           # 路径可达
    UNREACHABLE = "unreachable"       # 路径不可达
    UNKNOWN = "unknown"               # 未知（分析失败）


class RiskLevel(str, Enum):
    """风险等级"""
    HIGH = "high"       # 高风险：路径可达 + LLM 确认漏洞
    MEDIUM = "medium"   # 中风险：路径可达，待确认
    LOW = "low"         # 低风险：路径不可达
    UNKNOWN = "unknown" # 未知


@dataclass
class PathReachResult:
    """单个函数的路径可达性分析结果"""
    function_name: str
    status: PathReachStatus
    path_count: int
    risk_level: RiskLevel
    is_vulnerable: bool = False
    vuln_type: Optional[str] = None
    analysis_summary: Optional[str] = None
    paths: List[Dict[str, Any]] = field(default_factory=list)
    llm_results: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "function_name": self.function_name,
            "status": self.status.value,
            "path_count": self.path_count,
            "risk_level": self.risk_level.value,
            "is_vulnerable": self.is_vulnerable,
            "vuln_type": self.vuln_type,
            "analysis_summary": self.analysis_summary,
            "paths": self.paths,
            "llm_results": self.llm_results
        }


@dataclass
class PathReachSummary:
    """路径可达性分析汇总"""
    total_functions: int
    reachable_count: int
    unreachable_count: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int
    total_paths: int
    high_risk_functions: List[str]
    reachable_functions: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PathReachAgent:
    """路径可达性分析智能体"""

    def __init__(
        self,
        zero_day_agent_url: str = None,
        timeout: int = None,
    ):
        """
        Args:
            zero_day_agent_url: DeepauditExtension zero-day API 地址（默认从配置读取）
            timeout: 请求超时时间（秒，默认从配置读取）
        """
        self.zero_day_agent_url = zero_day_agent_url or self._get_default_url()
        self.timeout = timeout or self._get_default_timeout()
        self.name = "Path Reach Agent"

    def _get_default_url(self) -> str:
        """从配置获取 zero-day 路径分析服务地址"""
        try:
            if config_manager.config.has_section('ZERO_DAY_AGENT'):
                return config_manager.config.get(
                    'ZERO_DAY_AGENT',
                    'service_url',
                    fallback='http://localhost:8000/api/v1/zero-day-agent'
                ).rstrip('/')
            return "http://localhost:8000/api/v1/zero-day-agent"
        except Exception as e:
            logger.warning(f"读取 ZERO_DAY_AGENT 配置失败: {e}，使用默认值")
            return "http://localhost:8000/api/v1/zero-day-agent"

    def _get_default_timeout(self) -> int:
        """从配置获取超时时间"""
        try:
            if config_manager.config.has_section('ZERO_DAY_AGENT'):
                return config_manager.config.getint('ZERO_DAY_AGENT', 'timeout', fallback=600)
            return 600
        except Exception as e:
            logger.warning(f"读取 ZERO_DAY_AGENT timeout 配置失败: {e}，使用默认值")
            return 600

    def _get_path_reachable_url(self) -> str:
        """构造路径分析接口地址。"""
        return f"{self.zero_day_agent_url}/path-reachable"

    async def analyze_reachability(
        self,
        binary_path: str,
        vulnerable_functions: List[str],
        cwe_type: Optional[str] = None,
        additional_sources: Optional[List[str]] = None,
        skip_vulfunc_rank: bool = False,
        send_message: Optional[Callable] = None,
    ) -> Dict[str, PathReachResult]:
        """
        分析漏洞函数的路径可达性

        Args:
            binary_path: 二进制文件路径
            vulnerable_functions: Detection Agent 认定的漏洞函数列表
            cwe_type: CWE 类型
            additional_sources: 额外的 source 函数
            skip_vulfunc_rank: 是否跳过 vulfunc_rank（仅使用提供的函数）
            send_message: 消息发送回调

        Returns:
            函数名 -> PathReachResult 的映射
        """
        if send_message:
            await send_message(
                content=f"开始分析 {len(vulnerable_functions)} 个漏洞函数的路径可达性",
                message_type="header2"
            )

        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "binary_path": binary_path,
                    "vulnerable_functions": vulnerable_functions,
                    "cwe_type": cwe_type,
                    "additional_sources": additional_sources,
                    "skip_vulfunc_rank": skip_vulfunc_rank
                }

                url = self._get_path_reachable_url()
                logger.info(f"[PathReachAgent] 调用路径分析 API: {url}")
                logger.info(f"[PathReachAgent] 请求参数: {json.dumps(payload, ensure_ascii=False)}")

                if send_message:
                    await send_message(
                        content=f"正在调用路径分析服务...\n目标函数: {', '.join(vulnerable_functions[:5])}{'...' if len(vulnerable_functions) > 5 else ''}",
                        message_type="message"
                    )

                async with session.post(
                    url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        logger.error(f"[PathReachAgent] API 调用失败: {response.status} - {error_text}")
                        if send_message:
                            await send_message(
                                content=f"路径分析服务调用失败: {error_text[:200]}",
                                message_type="message"
                            )
                        return self._create_error_results(vulnerable_functions)

                    result = await response.json()

        except asyncio.TimeoutError:
            logger.error("[PathReachAgent] API 调用超时")
            if send_message:
                await send_message(
                    content="路径可达性分析超时，请检查 DeepauditExtension 路径分析服务状态",
                    message_type="message"
                )
            return self._create_error_results(vulnerable_functions)

        except aiohttp.ClientConnectorError as e:
            logger.error(f"[PathReachAgent] 无法连接到路径分析服务: {e}")
            if send_message:
                await send_message(
                    content=f"无法连接到路径分析服务 ({self.zero_day_agent_url})，请确保 DeepauditExtension 后端已启动",
                    message_type="message"
                )
            return self._create_error_results(vulnerable_functions)

        except Exception as e:
            logger.error(f"[PathReachAgent] API 调用异常: {e}", exc_info=True)
            if send_message:
                await send_message(
                    content=f"路径可达性分析失败: {str(e)}",
                    message_type="message"
                )
            return self._create_error_results(vulnerable_functions)

        parsed_results = self._parse_results(result, vulnerable_functions)

        if send_message:
            summary = self.get_summary(parsed_results)
            await send_message(
                content=f"路径分析完成：{summary.reachable_count}/{summary.total_functions} 个函数可达，{summary.high_risk_count} 个高风险",
                message_type="message"
            )

        return parsed_results

    def _parse_results(
        self,
        api_result: Dict[str, Any],
        vulnerable_functions: List[str]
    ) -> Dict[str, PathReachResult]:
        """解析 API 返回结果"""
        results = {}

        func_results = api_result.get("results", {})

        for func in vulnerable_functions:
            func_info = func_results.get(func, {})

            status_str = func_info.get("status", "unknown")
            if status_str == "reachable":
                status = PathReachStatus.REACHABLE
            elif status_str == "unreachable":
                status = PathReachStatus.UNREACHABLE
            else:
                status = PathReachStatus.UNKNOWN

            risk_str = func_info.get("risk_level", "unknown")
            try:
                risk_level = RiskLevel(risk_str)
            except ValueError:
                risk_level = RiskLevel.UNKNOWN

            results[func] = PathReachResult(
                function_name=func,
                status=status,
                path_count=func_info.get("path_count", 0),
                risk_level=risk_level,
                is_vulnerable=func_info.get("is_vulnerable", False),
                vuln_type=func_info.get("vuln_type"),
                analysis_summary=func_info.get("analysis_summary"),
                paths=func_info.get("paths", []),
                llm_results=func_info.get("llm_results", [])
            )

        return results

    def _create_error_results(
        self,
        vulnerable_functions: List[str]
    ) -> Dict[str, PathReachResult]:
        """创建错误状态的结果"""
        return {
            func: PathReachResult(
                function_name=func,
                status=PathReachStatus.UNKNOWN,
                path_count=0,
                risk_level=RiskLevel.UNKNOWN,
                is_vulnerable=False
            )
            for func in vulnerable_functions
        }

    def get_summary(self, results: Dict[str, PathReachResult]) -> PathReachSummary:
        """获取分析汇总"""
        total = len(results)
        reachable = [f for f, r in results.items() if r.status == PathReachStatus.REACHABLE]
        unreachable = [f for f, r in results.items() if r.status == PathReachStatus.UNREACHABLE]

        high_risk = [f for f, r in results.items() if r.risk_level == RiskLevel.HIGH]
        medium_risk = [f for f, r in results.items() if r.risk_level == RiskLevel.MEDIUM]
        low_risk = [f for f, r in results.items() if r.risk_level == RiskLevel.LOW]

        total_paths = sum(r.path_count for r in results.values())

        return PathReachSummary(
            total_functions=total,
            reachable_count=len(reachable),
            unreachable_count=len(unreachable),
            high_risk_count=len(high_risk),
            medium_risk_count=len(medium_risk),
            low_risk_count=len(low_risk),
            total_paths=total_paths,
            high_risk_functions=high_risk,
            reachable_functions=reachable
        )

    def format_results_for_display(
        self,
        results: Dict[str, PathReachResult]
    ) -> str:
        """格式化结果用于展示"""
        lines = ["## 路径可达性分析结果\n"]

        summary = self.get_summary(results)
        lines.append(f"**汇总**: 共分析 {summary.total_functions} 个函数，"
                     f"{summary.reachable_count} 个可达，"
                     f"{summary.total_paths} 条路径\n")

        high_risk = [(f, r) for f, r in results.items() if r.risk_level == RiskLevel.HIGH]
        medium_risk = [(f, r) for f, r in results.items() if r.risk_level == RiskLevel.MEDIUM]
        low_risk = [(f, r) for f, r in results.items() if r.risk_level == RiskLevel.LOW]
        unknown = [(f, r) for f, r in results.items() if r.risk_level == RiskLevel.UNKNOWN]

        if high_risk:
            lines.append("\n### 高风险（路径可达 + LLM确认漏洞）")
            for func, result in high_risk:
                lines.append(f"\n**{func}**: {result.path_count} 条可达路径")
                if result.vuln_type:
                    lines.append(f"- 漏洞类型: {result.vuln_type}")
                if result.analysis_summary:
                    summary_text = result.analysis_summary[:300]
                    if len(result.analysis_summary) > 300:
                        summary_text += "..."
                    lines.append(f"- 分析: {summary_text}")

        if medium_risk:
            lines.append("\n### 中风险（路径可达，需人工确认）")
            for func, result in medium_risk:
                lines.append(f"- **{func}**: {result.path_count} 条可达路径")

        if low_risk:
            lines.append("\n### 低风险（路径不可达）")
            for func, result in low_risk:
                lines.append(f"- **{func}**: 未找到从外部输入的可达路径")

        if unknown:
            lines.append("\n### 未知（分析失败）")
            for func, result in unknown:
                lines.append(f"- **{func}**: 分析状态未知")

        return "\n".join(lines)

    def save_results(
        self,
        results: Dict[str, PathReachResult],
        output_path: str
    ) -> None:
        """保存分析结果到文件"""
        output_data = {
            "summary": self.get_summary(results).to_dict(),
            "results": {func: result.to_dict() for func, result in results.items()}
        }

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output_data, f, ensure_ascii=False, indent=2)

        logger.info(f"[PathReachAgent] 结果已保存到: {output_path}")
