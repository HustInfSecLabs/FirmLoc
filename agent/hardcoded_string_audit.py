import json
import os
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from log import logger
from model import AgentModel, ChatModel
from agent.ida_toolkits import IdaToolkit
from config import config_manager
from utils.utils import get_binary_architecture, is_binary_file


class HardcodedStringAuditor:
    """Use IDA + LLM to review hardcoded strings in a binary with multi-round filtering."""

    # 置信度阈值：第一轮粗筛后保留的最低置信度
    CONFIDENCE_THRESHOLD_ROUND1 = 0.5
    # 最终报告的置信度阈值
    CONFIDENCE_THRESHOLD_FINAL = 0.6
    # 是否启用二次精筛
    ENABLE_SECOND_ROUND = True
    # 二次精筛的批次大小（条目数，不是字符串数）
    SECOND_ROUND_BATCH_SIZE = 100

    def __init__(
        self,
        model: Optional[ChatModel] = None,
        ida_service_url: Optional[str] = None,
        output_root: Optional[str] = None,
    ) -> None:
        self.model: ChatModel = model or AgentModel("DeepSeek")
        self.ida_toolkit = IdaToolkit()
        self.ida_service_url = (ida_service_url or config_manager.config["IDA_SERVICE"]["service_url"]).rstrip("/")
        self.output_root = Path(output_root or config_manager.config["result.path"]["savedir"])

    async def audit(
        self,
        binary_path: str,
        chat_id: Optional[str] = None,
        ida_version: Optional[str] = None,
        max_strings: int = 1000000,
    ) -> Dict[str, Any]:
        if not os.path.exists(binary_path) or not is_binary_file(binary_path):
            raise FileNotFoundError(f"Invalid binary file: {binary_path}")

        ida_version = ida_version or get_binary_architecture(binary_path)
        endpoint = f"{self.ida_service_url}/export_strings"

        logger.info("[StringAudit] start extraction via IDA service: %s", endpoint)
        ida_result = await self.ida_toolkit.extract_strings(
            binary_path,
            ida_version=ida_version,
            string_url=endpoint,
        )

        total_strings = int(ida_result.get("count", 0)) if isinstance(ida_result, dict) else 0
        raw_strings: List[Dict[str, Any]] = []
        if isinstance(ida_result, dict):
            raw_strings = list(ida_result.get("strings", []))

        filtered = self._filter_strings(raw_strings, max_strings=max_strings)
        
        # 分批处理，避免超出 LLM 上下文限制
        # 10000 strings is too large for context window (229k tokens > 163k limit)
        # Reducing batch size to 2000 strings per batch
        BATCH_SIZE = 2000  
        all_suspicious_entries = []
        batch_results = []
        
        # 如果过滤后的字符串数量超过 BATCH_SIZE，则分批处理
        if len(filtered) > BATCH_SIZE:
            logger.info(f"[StringAudit] Total strings {len(filtered)} exceeds batch size {BATCH_SIZE}, splitting into batches...")
            
            for i in range(0, len(filtered), BATCH_SIZE):
                batch = filtered[i:i + BATCH_SIZE]
                logger.info(f"[StringAudit] Processing batch {i//BATCH_SIZE + 1}/{(len(filtered)-1)//BATCH_SIZE + 1} ({len(batch)} strings)")
                
                prompt = self._build_prompt(binary_path, batch, total_strings, is_batch=True)
                llm_raw = self.model.chat(prompt=prompt)
                parsed = self._safe_json(llm_raw)
                retry_done = False
                if parsed is None:
                    # 追加一次纠错重试，提示仅返回 JSON
                    retry_prompt = prompt + "\n\nPrevious reply was not valid JSON. Output STRICT JSON only, no markdown, keys: summary, risk_level, suspicious_entries[]."
                    llm_raw_retry = self.model.chat(prompt=retry_prompt)
                    parsed = self._safe_json(llm_raw_retry)
                    retry_done = True
                
                if parsed and isinstance(parsed, dict):
                    entries = parsed.get("suspicious_entries", [])
                    if isinstance(entries, list):
                        all_suspicious_entries.extend(entries)
                    batch_results.append(parsed)
                else:
                    # 记录更详细的错误日志，包括原始响应的前后部分，便于排查 JSON 格式问题
                    preview_len = 500
                    raw_preview = llm_raw[:preview_len] + "..." if len(llm_raw) > preview_len else llm_raw
                    logger.warning(f"[StringAudit] Failed to parse batch result. Raw response preview:\n{raw_preview}")
                    if retry_done:
                        raw_preview_retry = llm_raw_retry[:preview_len] + "..." if len(llm_raw_retry) > preview_len else llm_raw_retry
                        logger.warning(f"[StringAudit] Retry response preview:\n{raw_preview_retry}")
                    
                    # 尝试将错误的响应保存到文件，以便后续分析
                    try:
                        debug_dir = self.output_root / (chat_id or "debug") / "failed_batches"
                        debug_dir.mkdir(parents=True, exist_ok=True)
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                        debug_file = debug_dir / f"batch_fail_{timestamp}.txt"
                        with open(debug_file, "w", encoding="utf-8") as f:
                            f.write(f"Batch Index: {i//BATCH_SIZE + 1}\n")
                            f.write(f"Prompt Length: {len(prompt)}\n")
                            f.write("-" * 50 + "\n")
                            f.write(llm_raw)
                            if retry_done:
                                f.write("\n" + "-" * 50 + "\n")
                                f.write("[Retry]\n")
                                f.write(llm_raw_retry)
                        logger.warning(f"[StringAudit] Saved failed batch response to: {debug_file}")
                    except Exception as e:
                        logger.error(f"[StringAudit] Failed to save debug info: {e}")

            # 聚合结果
            final_risk_level = "low"
            risk_levels = {r.get("risk_level", "low").lower() for r in batch_results}
            if "high" in risk_levels:
                final_risk_level = "high"
            elif "medium" in risk_levels:
                final_risk_level = "medium"
                
            # 生成汇总摘要
            summary = f"Analyzed {len(filtered)} strings in {len(batch_results)} batches. Found {len(all_suspicious_entries)} suspicious entries."
            if all_suspicious_entries:
                summary += " Key findings include potential credentials or sensitive data."
            
            llm_parsed = {
                "summary": summary,
                "risk_level": final_risk_level,
                "suspicious_entries": all_suspicious_entries
            }
            llm_raw = json.dumps(llm_parsed, ensure_ascii=False)  # 构造一个合成的 raw 响应
            
        else:
            # 数量较少，一次性处理
            prompt = self._build_prompt(binary_path, filtered, total_strings)
            logger.info("[StringAudit] sending %d strings to LLM", len(filtered))
            llm_raw = self.model.chat(prompt=prompt)
            llm_parsed = self._safe_json(llm_raw)
            if llm_parsed and isinstance(llm_parsed, dict):
                all_suspicious_entries = llm_parsed.get("suspicious_entries", [])

        # ========== 第一轮筛选完成，开始后处理 ==========
        
        # 1. 置信度过滤
        filtered_entries = self._filter_by_confidence(
            all_suspicious_entries, 
            threshold=self.CONFIDENCE_THRESHOLD_ROUND1
        )
        logger.info(f"[StringAudit] Round 1 complete: {len(all_suspicious_entries)} -> {len(filtered_entries)} entries after confidence filter (>={self.CONFIDENCE_THRESHOLD_ROUND1})")
        
        # 2. 去重和聚合同类条目
        deduplicated_entries = self._deduplicate_entries(filtered_entries)
        logger.info(f"[StringAudit] After deduplication: {len(deduplicated_entries)} entries")
        
        # 3. 二次精筛（可选）
        if self.ENABLE_SECOND_ROUND and len(deduplicated_entries) > 50:
            logger.info(f"[StringAudit] Starting Round 2 refinement for {len(deduplicated_entries)} entries...")
            refined_entries = await self._second_round_review(
                binary_path, deduplicated_entries, chat_id
            )
            logger.info(f"[StringAudit] Round 2 complete: {len(deduplicated_entries)} -> {len(refined_entries)} entries")
            final_entries = refined_entries
        else:
            final_entries = deduplicated_entries
        
        # 4. 最终置信度过滤
        final_entries = self._filter_by_confidence(
            final_entries,
            threshold=self.CONFIDENCE_THRESHOLD_FINAL
        )
        logger.info(f"[StringAudit] Final entries after confidence filter (>={self.CONFIDENCE_THRESHOLD_FINAL}): {len(final_entries)}")
        
        # 5. 按类别和置信度排序
        final_entries = self._sort_entries(final_entries)
        
        # 重新计算风险等级
        final_risk_level = self._calculate_risk_level(final_entries)
        
        # 生成最终汇总
        final_summary = self._generate_summary(len(filtered), final_entries)
        
        llm_parsed = {
            "summary": final_summary,
            "risk_level": final_risk_level,
            "suspicious_entries": final_entries,
            "statistics": self._generate_statistics(all_suspicious_entries, final_entries)
        }
        llm_raw = json.dumps(llm_parsed, ensure_ascii=False)

        artifact_path = self._persist_results(
            binary_path=binary_path,
            chat_id=chat_id,
            raw_strings=raw_strings,
            filtered=filtered,
            llm_raw=llm_raw,
            llm_parsed=llm_parsed,
        )

        return {
            "binary": os.path.basename(binary_path),
            "ida_version": ida_version,
            "total_strings": total_strings,
            "strings_analyzed": len(filtered),
            "strings": filtered,
            "llm_raw": llm_raw,
            "llm_parsed": llm_parsed,
            "artifact_path": artifact_path,
        }

    def _filter_strings(self, strings: List[Dict[str, Any]], max_strings: int = 1000000) -> List[Dict[str, Any]]:
        # 增加默认 max_strings 上限，因为现在支持分批了
        seen = set()
        filtered: List[Dict[str, Any]] = []
        for entry in strings:
            value = str(entry.get("value", "")).strip()
            if not value or len(value) < 4:
                continue
            key = value.lower()
            if key in seen:
                continue
            seen.add(key)
            filtered.append({
                "value": value,
                "address": entry.get("address"),
                "section": entry.get("section"),
                "length": entry.get("length"),
            })
            if len(filtered) >= max_strings:
                break
        return filtered

    def _build_prompt(self, binary_path: str, strings: List[Dict[str, Any]], total_strings: int, is_batch: bool = False) -> str:
        header = f"Binary: {os.path.basename(binary_path)}\nTotal strings: {total_strings}\nAnalyzed strings (deduped & truncated): {len(strings)}"

        lines = []
        for idx, item in enumerate(strings, 1):
            addr = item.get("address") or "?"
            sec = item.get("section") or "?"
            val = item.get("value") or ""
            lines.append(f"{idx}. [addr={addr}][sec={sec}] {val}")
            
        batch_instruction = ""
        if is_batch:
            batch_instruction = "Note: This is a partial batch of strings from the binary. Analyze them independently."

        return (
            "You are a firmware/binary security analyst. Review hardcoded strings extracted by IDA and flag risk indicators.\n"
            f"{batch_instruction}\n"
            "Focus on: (1) credentials (user/pass, tokens, keys), (2) SQL statements, (3) command injection payloads, "
            "(4) firmware/middleware product names & versions, (5) preset/backdoor users, (6) suspicious encrypted or high-entropy blobs.\n"
            "Be concise and only include strings that are suspicious or security-relevant.\n"
            "IMPORTANT: Do not modify the string values. Return them exactly as they appear in the input list.\n"
            "Return STRICT JSON ONLY (no Markdown/code fences) with keys: summary (string), risk_level (low/medium/high), "
            "suspicious_entries (array of {value, category, reason, address, section, confidence[0-1]}).\n"
            "If no issues or not enough evidence, set suspicious_entries=[] and risk_level='low'.\n"
            "Remove or escape any control / non-printable characters before output.\n"
            f"\nContext:\n{header}\n\nStrings:\n" + "\n".join(lines)
        )

    def _safe_json(self, text: str) -> Any:
        if not text:
            return None
        text = text.strip()
        
        # 更健壮的 Markdown 代码块去除
        # 处理 ```json ... ``` 或 ``` ... ``` 格式
        import re
        # 1) 去除 Markdown 代码块（```json ... ``` 或 ``` ... ```）
        code_block_pattern = re.compile(r'^```(?:json)?\s*\n?(.*?)\n?```\s*$', re.DOTALL | re.IGNORECASE)
        match = code_block_pattern.match(text)
        if match:
            text = match.group(1).strip()
        elif text.startswith("```"):
            lines = text.splitlines()
            if lines and lines[0].strip().startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines).strip()

        # 2) 提前剥离最外层 { ... }，避免多余前后缀影响
        brace_start = text.find("{")
        brace_end = text.rfind("}")
        if brace_start != -1 and brace_end != -1 and brace_end > brace_start:
            text = text[brace_start:brace_end + 1].strip()
        
        # 修复非法的 JSON 转义序列 + 非打印控制字符
        # JSON 只允许: \" \\ \/ \b \f \n \r \t \uXXXX
        # LLM 可能返回类似 \E \Y \Z 等非法转义，需要将单个 \ 转为 \\，并转义 0x00-0x1F 控制符
        def fix_invalid_escapes(s: str) -> str:
            # 先转义控制字符（除标准 \n\r\t 等外的其他 0x00-0x1F）
            def escape_ctrl(m):
                ch = m.group(0)
                return f"\\u{ord(ch):04x}"

            s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", escape_ctrl, s)

            # 再处理非法反斜杠转义
            result = []
            i = 0
            while i < len(s):
                if s[i] == '\\' and i + 1 < len(s):
                    next_char = s[i + 1]
                    if next_char in '"\\bfnrtu/':
                        # 合法转义，保持原样
                        result.append(s[i])
                        result.append(next_char)
                        i += 2
                    else:
                        # 非法转义，添加额外的反斜杠
                        result.append('\\\\')
                        result.append(next_char)
                        i += 2
                else:
                    result.append(s[i])
                    i += 1
            return ''.join(result)
        
        # 3) 先尝试直接解析
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # 4) 尝试修复非法转义和控制字符后再解析
        try:
            fixed_text = fix_invalid_escapes(text)
            return json.loads(fixed_text)
        except Exception:
            pass

        # 5) 兜底：再取一次最外层 { ... }，并再次修复
        try:
            start_idx = text.find("{")
            end_idx = text.rfind("}")
            if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                json_text = text[start_idx:end_idx+1]
                json_text = fix_invalid_escapes(json_text)
                return json.loads(json_text)
        except Exception:
            pass

        return None

    def _persist_results(
        self,
        binary_path: str,
        chat_id: Optional[str],
        raw_strings: List[Dict[str, Any]],
        filtered: List[Dict[str, Any]],
        llm_raw: str,
        llm_parsed: Any,
    ) -> Optional[str]:
        try:
            run_dir = self.output_root / (chat_id or "string_audit") / "string_audit"
            run_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_file = run_dir / f"{Path(binary_path).stem}_string_audit_{stamp}.json"
            payload = {
                "binary": os.path.basename(binary_path),
                "raw_strings": raw_strings,
                "filtered": filtered,
                "llm_raw": llm_raw,
                "llm_parsed": llm_parsed,
            }
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            return str(out_file)
        except Exception as exc:
            logger.warning("Persist string audit result failed: %s", exc)
            return None

    # ==================== 多轮筛选相关方法 ====================

    def _filter_by_confidence(
        self, entries: List[Dict[str, Any]], threshold: float
    ) -> List[Dict[str, Any]]:
        """按置信度过滤条目"""
        return [
            e for e in entries 
            if float(e.get("confidence", 0)) >= threshold
        ]

    def _deduplicate_entries(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """去重并聚合同类条目"""
        seen_values = {}
        deduplicated = []
        
        for entry in entries:
            value = entry.get("value", "").strip().lower()
            if not value:
                continue
            
            # 如果已存在相同值，保留置信度更高的
            if value in seen_values:
                existing_idx = seen_values[value]
                if float(entry.get("confidence", 0)) > float(deduplicated[existing_idx].get("confidence", 0)):
                    deduplicated[existing_idx] = entry
            else:
                seen_values[value] = len(deduplicated)
                deduplicated.append(entry)
        
        return deduplicated

    def _sort_entries(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """按类别优先级和置信度排序"""
        # 类别优先级（数字越小越优先）
        category_priority = {
            "credentials": 1,
            "backdoor_user": 2,
            "hardcoded_key": 3,
            "sql_injection": 4,
            "command_injection": 5,
            "network_service": 6,
            "firmware_version": 7,
            "debug_pattern": 8,
        }
        
        def sort_key(entry):
            category = entry.get("category", "other").lower()
            # 匹配最接近的类别
            priority = 100
            for key, val in category_priority.items():
                if key in category:
                    priority = val
                    break
            confidence = float(entry.get("confidence", 0))
            return (priority, -confidence)
        
        return sorted(entries, key=sort_key)

    def _calculate_risk_level(self, entries: List[Dict[str, Any]]) -> str:
        """根据条目计算整体风险等级"""
        if not entries:
            return "low"
        
        high_risk_categories = {"credentials", "backdoor", "hardcoded_key", "sql", "command"}
        high_confidence_count = 0
        high_risk_count = 0
        
        for entry in entries:
            confidence = float(entry.get("confidence", 0))
            category = entry.get("category", "").lower()
            
            if confidence >= 0.8:
                high_confidence_count += 1
            
            for risk_cat in high_risk_categories:
                if risk_cat in category:
                    high_risk_count += 1
                    break
        
        if high_risk_count >= 3 or (high_risk_count >= 1 and high_confidence_count >= 5):
            return "high"
        elif high_risk_count >= 1 or high_confidence_count >= 3:
            return "medium"
        else:
            return "low"

    def _generate_summary(self, total_analyzed: int, final_entries: List[Dict[str, Any]]) -> str:
        """生成最终汇总"""
        if not final_entries:
            return f"Analyzed {total_analyzed} strings. No significant security issues found after multi-round review."
        
        # 统计各类别数量
        category_counts = defaultdict(int)
        for entry in final_entries:
            category = entry.get("category", "other")
            category_counts[category] += 1
        
        top_categories = sorted(category_counts.items(), key=lambda x: -x[1])[:3]
        category_summary = ", ".join([f"{cat}: {count}" for cat, count in top_categories])
        
        return (
            f"Analyzed {total_analyzed} strings through multi-round review. "
            f"Found {len(final_entries)} high-confidence suspicious entries. "
            f"Top categories: {category_summary}."
        )

    def _generate_statistics(
        self, 
        round1_entries: List[Dict[str, Any]], 
        final_entries: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """生成筛选统计信息"""
        category_counts = defaultdict(int)
        for entry in final_entries:
            category = entry.get("category", "other")
            category_counts[category] += 1
        
        return {
            "round1_count": len(round1_entries),
            "final_count": len(final_entries),
            "reduction_rate": f"{(1 - len(final_entries) / max(len(round1_entries), 1)) * 100:.1f}%",
            "category_distribution": dict(category_counts)
        }

    async def _second_round_review(
        self, 
        binary_path: str, 
        entries: List[Dict[str, Any]],
        chat_id: Optional[str]
    ) -> List[Dict[str, Any]]:
        """第二轮精筛：让 LLM 对初筛结果进行复审"""
        refined_entries = []
        
        # 分批处理
        for i in range(0, len(entries), self.SECOND_ROUND_BATCH_SIZE):
            batch = entries[i:i + self.SECOND_ROUND_BATCH_SIZE]
            logger.info(f"[StringAudit] Round 2 batch {i//self.SECOND_ROUND_BATCH_SIZE + 1}/{(len(entries)-1)//self.SECOND_ROUND_BATCH_SIZE + 1}")
            
            prompt = self._build_refinement_prompt(binary_path, batch)
            llm_raw = self.model.chat(prompt=prompt)
            parsed = self._safe_json(llm_raw)
            
            if parsed and isinstance(parsed, dict):
                refined = parsed.get("refined_entries", [])
                if isinstance(refined, list):
                    refined_entries.extend(refined)
            else:
                # 解析失败时保留原条目（保守策略）
                logger.warning("[StringAudit] Round 2 parse failed, keeping original entries")
                refined_entries.extend(batch)
        
        return refined_entries

    def _build_refinement_prompt(
        self, binary_path: str, entries: List[Dict[str, Any]]
    ) -> str:
        """构建二次精筛的 Prompt"""
        entries_text = json.dumps(entries, ensure_ascii=False, indent=2)
        
        return (
            "You are a senior firmware security analyst performing a SECOND ROUND review.\n"
            "The following suspicious strings were flagged in the first round of analysis.\n"
            "Your task is to:\n"
            "1. REMOVE false positives (common library strings, version info without security impact, etc.)\n"
            "2. KEEP only entries that represent real security risks\n"
            "3. INCREASE confidence for truly dangerous entries (actual credentials, backdoors, etc.)\n"
            "4. DECREASE confidence or REMOVE low-value findings\n\n"
            "Categories to PRIORITIZE:\n"
            "- Hardcoded credentials (username/password pairs, API keys, tokens)\n"
            "- Backdoor accounts or hidden admin users\n"
            "- SQL injection or command injection patterns\n"
            "- Encryption keys or secrets\n\n"
            "Categories to be MORE STRICT about:\n"
            "- Version strings (only keep if they reveal exploitable vulnerabilities)\n"
            "- Debug patterns (only keep if they expose sensitive functionality)\n"
            "- High-entropy blobs (only keep if they appear to be actual keys/secrets)\n\n"
            f"Binary: {os.path.basename(binary_path)}\n\n"
            f"Entries to review:\n{entries_text}\n\n"
            "Return strict JSON with key 'refined_entries' containing the filtered array.\n"
            "Each entry should have: value, category, reason, address, section, confidence (0-1).\n"
            "Be aggressive in filtering. A good result has 30-50% fewer entries than input."
        )
