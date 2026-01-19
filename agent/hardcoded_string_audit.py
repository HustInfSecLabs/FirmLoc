import json
import os
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from log import logger
from model import AgentModel, ChatModel
from agent.ida_toolkits import IdaToolkit
from agent.jar_string_extractor import JarStringExtractor
from agent.context_aware_auditor import JarContextProvider, ReActStringAuditor
from config import config_manager
from utils.utils import get_binary_architecture, is_binary_file


def is_jar_file(file_path: str) -> bool:
    """Check if file is a JAR file."""
    return Path(file_path).suffix.lower() == '.jar'


def parse_confidence(value: Any) -> float:
    """Safely parse confidence value from LLM response.
    
    LLM may return:
    - float: 0.8, 0.95
    - int: 1, 0
    - str numeric: "0.8", "0.95"
    - str label: "high", "medium", "low", "critical"
    
    Returns a float between 0 and 1.
    """
    if value is None:
        return 0.0
    
    # If already a number
    if isinstance(value, (int, float)):
        # Normalize to 0-1 range if needed
        if value > 1:
            return min(value / 100.0, 1.0)  # Handle percentage like 85 -> 0.85
        return float(value)
    
    # If string
    if isinstance(value, str):
        value_lower = value.lower().strip()
        
        # Try parsing as number first
        try:
            num = float(value_lower.replace('%', ''))
            if num > 1:
                return min(num / 100.0, 1.0)
            return num
        except ValueError:
            pass
        
        # Map string labels to numeric values
        label_map = {
            "critical": 0.95,
            "high": 0.85,
            "medium": 0.65,
            "moderate": 0.65,
            "low": 0.35,
            "very low": 0.15,
            "none": 0.0,
            "unknown": 0.5,
        }
        
        for label, score in label_map.items():
            if label in value_lower:
                return score
        
        # Default for unrecognized strings
        logger.warning(f"[StringAudit] Unrecognized confidence value: '{value}', defaulting to 0.5")
        return 0.5
    
    return 0.0


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
    # 是否启用上下文感知审计（ReAct模式）
    ENABLE_CONTEXT_AWARE = True
    # 上下文感知审计的最大请求数
    MAX_CONTEXT_REQUESTS = 100
    
    # 需要上下文检查的模式 - 这些字符串单独看不确定，需要代码上下文
    CONTEXT_CHECK_PATTERNS = [
        r'^[a-zA-Z]+-reserved-',     # Reserved user patterns (e.g., viptela-reserved-uc)
        r'^[a-zA-Z]+-device-',       # Device user patterns
        r'^[a-zA-Z]+-service-',      # Service account patterns
        r'^[a-zA-Z]+-admin$',        # Admin user patterns
        r'validate.*user|verify.*user',  # User validation patterns
        r'\.cgi$|\.php$',            # CGI/PHP endpoints
    ]

    def __init__(
        self,
        model: Optional[ChatModel] = None,
        ida_service_url: Optional[str] = None,
        output_root: Optional[str] = None,
    ) -> None:
        self.model: ChatModel = model or AgentModel("DeepSeek")
        self.ida_toolkit = IdaToolkit()
        self.jar_extractor = JarStringExtractor()
        self.ida_service_url = (ida_service_url or config_manager.config["IDA_SERVICE"]["service_url"]).rstrip("/")
        self.output_root = Path(output_root or config_manager.config["result.path"]["savedir"])
        self._context_check_compiled = [re.compile(p, re.IGNORECASE) for p in self.CONTEXT_CHECK_PATTERNS]

    def _needs_context_check(self, value: str) -> bool:
        """Check if a string needs code context to properly assess."""
        for pattern in self._context_check_compiled:
            if pattern.search(value):
                return True
        return False

    async def audit(
        self,
        binary_path: str,
        chat_id: Optional[str] = None,
        ida_version: Optional[str] = None,
        max_strings: int = 1000000,
    ) -> Dict[str, Any]:
        file_path = Path(binary_path)
        
        # Determine file type and choose extraction method
        if is_jar_file(binary_path):
            # JAR file: use jadx-based extraction
            return await self._audit_jar(binary_path, chat_id, max_strings)
        
        # Binary file: use IDA-based extraction
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
        
        # Phase 1: LLM-based initial screening
        BATCH_SIZE = 2000
        all_suspicious_entries = []
        
        if len(filtered) > BATCH_SIZE:
            batch_results = []
            logger.info(f"[StringAudit] Total strings {len(filtered)} exceeds batch size {BATCH_SIZE}, splitting into batches...")
            
            for i in range(0, len(filtered), BATCH_SIZE):
                batch = filtered[i:i + BATCH_SIZE]
                logger.info(f"[StringAudit] Processing batch {i//BATCH_SIZE + 1}/{(len(filtered)-1)//BATCH_SIZE + 1} ({len(batch)} strings)")
                
                prompt = self._build_prompt(binary_path, batch, total_strings, is_batch=True)
                llm_raw = self.model.chat(prompt=prompt)
                parsed = self._safe_json(llm_raw)
                
                if not parsed:
                    retry_prompt = prompt + "\n\nPrevious reply was not valid JSON. Output STRICT JSON only."
                    llm_raw = self.model.chat(prompt=retry_prompt)
                    parsed = self._safe_json(llm_raw)
                
                if parsed and isinstance(parsed, dict):
                    entries = parsed.get("suspicious_entries", [])
                    if isinstance(entries, list):
                        all_suspicious_entries.extend(entries)
                    batch_results.append(parsed)
                else:
                    logger.warning(f"[StringAudit] Failed to parse batch {i//BATCH_SIZE + 1} result")

            # Aggregate results
            risk_levels = {r.get("risk_level", "low").lower() for r in batch_results}
            final_risk_level = "high" if "high" in risk_levels else "medium" if "medium" in risk_levels else "low"
            
            summary = f"Analyzed {len(filtered)} strings in {len(batch_results)} batches. Found {len(all_suspicious_entries)} suspicious entries."
            llm_parsed = {
                "summary": summary,
                "risk_level": final_risk_level,
                "suspicious_entries": all_suspicious_entries
            }
            llm_raw = json.dumps(llm_parsed, ensure_ascii=False)
            
        else:
            # Single batch processing
            prompt = self._build_prompt(binary_path, filtered, total_strings)
            llm_raw = self.model.chat(prompt=prompt)
            llm_parsed = self._safe_json(llm_raw)
            if llm_parsed and isinstance(llm_parsed, dict):
                all_suspicious_entries = llm_parsed.get("suspicious_entries", [])

        # Phase 2: Multi-round filtering
        filtered_entries = self._filter_by_confidence(all_suspicious_entries, self.CONFIDENCE_THRESHOLD_ROUND1)
        logger.info(f"[StringAudit] Round 1: {len(all_suspicious_entries)} -> {len(filtered_entries)} entries (confidence >= {self.CONFIDENCE_THRESHOLD_ROUND1})")
        
        deduplicated_entries = self._deduplicate_entries(filtered_entries)
        logger.info(f"[StringAudit] After deduplication: {len(deduplicated_entries)} entries")
        
        # Round 2 refinement (optional)
        if self.ENABLE_SECOND_ROUND and len(deduplicated_entries) > 50:
            logger.info(f"[StringAudit] Round 2: refining {len(deduplicated_entries)} entries...")
            final_entries = await self._second_round_review(binary_path, deduplicated_entries, chat_id)
            logger.info(f"[StringAudit] Round 2 complete: {len(final_entries)} entries")
        else:
            final_entries = deduplicated_entries
        
        # Final confidence filtering and sorting
        final_entries = self._filter_by_confidence(final_entries, self.CONFIDENCE_THRESHOLD_FINAL)
        final_entries = self._sort_entries(final_entries)
        logger.info(f"[StringAudit] Final: {len(final_entries)} entries (confidence >= {self.CONFIDENCE_THRESHOLD_FINAL})")
        
        # Phase 3: Binary context-aware analysis
        context_verified_entries = []
        if self.ENABLE_CONTEXT_AWARE and final_entries:
            context_verified_entries = await self._binary_context_aware_analysis(
                binary_path, filtered, final_entries, ida_version
            )
            if context_verified_entries:
                logger.info(f"[StringAudit] Context analysis: {len(context_verified_entries)}/{len(final_entries)} entries verified")
        
        # Calculate final risk and generate report
        final_risk_level = self._calculate_risk_level(final_entries)
        
        # Upgrade risk if context-verified entries indicate higher risk
        if context_verified_entries:
            context_risk = self._calculate_risk_level(context_verified_entries)
            risk_priority = {"low": 0, "medium": 1, "high": 2}
            if risk_priority.get(context_risk, 0) > risk_priority.get(final_risk_level, 0):
                final_risk_level = context_risk
        
        final_summary = self._generate_summary(len(filtered), final_entries, context_verified_entries)
        
        llm_parsed = {
            "summary": final_summary,
            "risk_level": final_risk_level,
            "suspicious_entries": final_entries,
            "context_verified_entries": context_verified_entries,
            "statistics": self._generate_statistics(all_suspicious_entries, final_entries, context_verified_entries)
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
        """Filter and deduplicate strings."""
        seen = set()
        filtered = []
        for entry in strings:
            value = str(entry.get("value", "")).strip()
            if len(value) < 4 or value.lower() in seen:
                continue
            seen.add(value.lower())
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
            "suspicious_entries (array of {value, category, reason, address, section, confidence}).\n"
            "The 'confidence' field MUST be a decimal number between 0.0 and 1.0 (e.g., 0.85), NOT a string like 'high'.\n"
            "If no issues or not enough evidence, set suspicious_entries=[] and risk_level='low'.\n"
            "Remove or escape any control / non-printable characters before output.\n"
            f"\nContext:\n{header}\n\nStrings:\n" + "\n".join(lines)
        )

    def _safe_json(self, text: str) -> Any:
        """Parse JSON from LLM response with error handling."""
        if not text:
            return None
        text = text.strip()
        
        # Remove markdown code blocks
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

        # Extract JSON object
        brace_start = text.find("{")
        brace_end = text.rfind("}")
        if brace_start != -1 and brace_end != -1 and brace_end > brace_start:
            text = text[brace_start:brace_end + 1].strip()
        
        # Fix invalid escape sequences
        def fix_escapes(s: str) -> str:
            s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", lambda m: f"\\u{ord(m.group(0)):04x}", s)
            result = []
            i = 0
            while i < len(s):
                if s[i] == '\\' and i + 1 < len(s):
                    next_char = s[i + 1]
                    if next_char in '"\\bfnrtu/':
                        result.append(s[i:i+2])
                        i += 2
                    else:
                        result.append('\\\\' + next_char)
                        i += 2
                else:
                    result.append(s[i])
                    i += 1
            return ''.join(result)
        
        # Try parsing
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            try:
                return json.loads(fix_escapes(text))
            except Exception:
                return None

    def _persist_results(
        self, binary_path: str, chat_id: Optional[str], raw_strings: List[Dict[str, Any]],
        filtered: List[Dict[str, Any]], llm_raw: str, llm_parsed: Any
    ) -> Optional[str]:
        """Save audit results to file."""
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
            logger.warning(f"Failed to persist results: {exc}")
            return None

    # Multi-round filtering methods
    
    def _filter_by_confidence(self, entries: List[Dict[str, Any]], threshold: float) -> List[Dict[str, Any]]:
        """Filter entries by confidence threshold."""
        return [e for e in entries if parse_confidence(e.get("confidence")) >= threshold]

    def _deduplicate_entries(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate entries, keeping higher confidence ones."""
        seen = {}
        deduplicated = []
        for entry in entries:
            value = entry.get("value", "").strip().lower()
            if not value:
                continue
            if value in seen:
                idx = seen[value]
                if parse_confidence(entry.get("confidence")) > parse_confidence(deduplicated[idx].get("confidence")):
                    deduplicated[idx] = entry
            else:
                seen[value] = len(deduplicated)
                deduplicated.append(entry)
        return deduplicated

    def _sort_entries(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort entries by category priority and confidence."""
        priority = {
            "credentials": 1, "backdoor": 2, "hardcoded_key": 3,
            "sql": 4, "command": 5, "network": 6, "firmware": 7, "debug": 8
        }
        def sort_key(entry):
            category = entry.get("category", "").lower()
            p = next((v for k, v in priority.items() if k in category), 100)
            return (p, -parse_confidence(entry.get("confidence")))
        return sorted(entries, key=sort_key)

    def _calculate_risk_level(self, entries: List[Dict[str, Any]]) -> str:
        """Calculate overall risk level."""
        if not entries:
            return "low"
        high_risk = {"credentials", "backdoor", "hardcoded_key", "sql", "command"}
        high_conf_count = sum(1 for e in entries if parse_confidence(e.get("confidence")) >= 0.8)
        high_risk_count = sum(1 for e in entries if any(r in e.get("category", "").lower() for r in high_risk))
        
        if high_risk_count >= 3 or (high_risk_count >= 1 and high_conf_count >= 5):
            return "high"
        elif high_risk_count >= 1 or high_conf_count >= 3:
            return "medium"
        return "low"

    def _generate_summary(
        self, total: int, final_entries: List[Dict[str, Any]], 
        context_entries: Optional[List[Dict[str, Any]]] = None
    ) -> str:
        """Generate summary."""
        if not final_entries:
            return f"Analyzed {total} strings. No significant security issues found."
        
        categories = defaultdict(int)
        for e in final_entries:
            categories[e.get("category", "other")] += 1
        top = ", ".join([f"{cat}: {count}" for cat, count in sorted(categories.items(), key=lambda x: -x[1])[:3]])
        
        summary = f"Analyzed {total} strings. Found {len(final_entries)} suspicious entries. Top categories: {top}."
        if context_entries:
            summary += f" {len(context_entries)} verified via code context."
        return summary

    def _generate_statistics(
        self, round1: List[Dict[str, Any]], final: List[Dict[str, Any]],
        context: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Generate filtering statistics."""
        categories = defaultdict(int)
        for e in final:
            categories[e.get("category", "other")] += 1
        
        stats = {
            "round1_count": len(round1),
            "final_count": len(final),
            "reduction_rate": f"{(1 - len(final) / max(len(round1), 1)) * 100:.1f}%",
            "category_distribution": dict(categories)
        }
        
        if context:
            context_cats = defaultdict(int)
            for e in context:
                context_cats[e.get("category", "other")] += 1
            stats["context_verified_count"] = len(context)
            stats["context_verified_rate"] = f"{len(context) / max(len(final), 1) * 100:.1f}%"
            stats["context_category_distribution"] = dict(context_cats)
        
        return stats

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

    # ==================== JAR 文件审计 ====================

    async def _audit_jar(
        self,
        jar_path: str,
        chat_id: Optional[str],
        max_strings: int = 100000
    ) -> Dict[str, Any]:
        """Audit a JAR file for hardcoded strings."""
        logger.info(f"[StringAudit] Starting JAR audit for {jar_path}")
        
        # Extract strings using jadx
        jar_result = self.jar_extractor.extract_strings(jar_path, max_strings)
        
        total_strings = jar_result.get("count", 0)
        raw_strings = jar_result.get("strings", [])
        extraction_method = jar_result.get("extraction_method", "unknown")
        
        logger.info(f"[StringAudit] Extracted {total_strings} strings using {extraction_method}")
        
        # Convert to standard format for LLM analysis
        filtered = self._filter_jar_strings(raw_strings, max_strings=max_strings)
        
        # Batch processing (same as binary audit)
        BATCH_SIZE = 2000
        all_suspicious_entries = []
        batch_results = []
        
        if len(filtered) > BATCH_SIZE:
            logger.info(f"[StringAudit] JAR: Total strings {len(filtered)} exceeds batch size {BATCH_SIZE}, splitting...")
            
            for i in range(0, len(filtered), BATCH_SIZE):
                batch = filtered[i:i + BATCH_SIZE]
                logger.info(f"[StringAudit] JAR: Processing batch {i//BATCH_SIZE + 1}/{(len(filtered)-1)//BATCH_SIZE + 1}")
                
                prompt = self._build_jar_prompt(jar_path, batch, total_strings, is_batch=True)
                llm_raw = self.model.chat(prompt=prompt)
                parsed = self._safe_json(llm_raw)
                
                if parsed and isinstance(parsed, dict):
                    entries = parsed.get("suspicious_entries", [])
                    if isinstance(entries, list):
                        all_suspicious_entries.extend(entries)
                    batch_results.append(parsed)
                else:
                    logger.warning(f"[StringAudit] JAR: Failed to parse batch result")
        else:
            prompt = self._build_jar_prompt(jar_path, filtered, total_strings)
            logger.info(f"[StringAudit] JAR: Sending {len(filtered)} strings to LLM")
            llm_raw = self.model.chat(prompt=prompt)
            llm_parsed = self._safe_json(llm_raw)
            if llm_parsed and isinstance(llm_parsed, dict):
                all_suspicious_entries = llm_parsed.get("suspicious_entries", [])

        # Multi-round filtering
        filtered_entries = self._filter_by_confidence(all_suspicious_entries, self.CONFIDENCE_THRESHOLD_ROUND1)
        logger.info(f"[StringAudit] JAR: Round 1: {len(all_suspicious_entries)} -> {len(filtered_entries)} entries")
        
        deduplicated_entries = self._deduplicate_entries(filtered_entries)
        
        if self.ENABLE_SECOND_ROUND and len(deduplicated_entries) > 50:
            logger.info(f"[StringAudit] JAR: Starting Round 2 for {len(deduplicated_entries)} entries")
            refined_entries = await self._second_round_review(jar_path, deduplicated_entries, chat_id)
            final_entries = refined_entries
        else:
            final_entries = deduplicated_entries
        
        # ==================== Phase 3: Context-Aware Analysis ====================
        # Check for strings that need code context to properly assess
        context_findings = []
        if self.ENABLE_CONTEXT_AWARE:
            context_findings = await self._context_aware_analysis(
                jar_path, filtered, final_entries
            )
            if context_findings:
                logger.info(f"[StringAudit] JAR: Context analysis found {len(context_findings)} additional findings")
                final_entries.extend(context_findings)
        
        final_entries = self._filter_by_confidence(final_entries, self.CONFIDENCE_THRESHOLD_FINAL)
        final_entries = self._deduplicate_entries(final_entries)  # Dedupe again after adding context findings
        final_entries = self._sort_entries(final_entries)
        
        final_risk_level = self._calculate_risk_level(final_entries)
        final_summary = self._generate_summary(len(filtered), final_entries)
        
        llm_parsed = {
            "summary": final_summary,
            "risk_level": final_risk_level,
            "suspicious_entries": final_entries,
            "statistics": self._generate_statistics(all_suspicious_entries, final_entries)
        }
        llm_raw = json.dumps(llm_parsed, ensure_ascii=False)
        
        # Persist results
        artifact_path = self._persist_results(
            binary_path=jar_path,
            chat_id=chat_id,
            raw_strings=raw_strings,
            filtered=filtered,
            llm_raw=llm_raw,
            llm_parsed=llm_parsed,
        )
        
        return {
            "binary": os.path.basename(jar_path),
            "file_type": "jar",
            "extraction_method": extraction_method,
            "total_strings": total_strings,
            "strings_analyzed": len(filtered),
            "strings": filtered,
            "llm_raw": llm_raw,
            "llm_parsed": llm_parsed,
            "artifact_path": artifact_path,
        }

    def _filter_jar_strings(self, strings: List[Dict[str, Any]], max_strings: int) -> List[Dict[str, Any]]:
        """Filter JAR strings for analysis."""
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
                "address": entry.get("class_name", "") + ":" + str(entry.get("line", 0)),
                "section": entry.get("file", ""),
                "length": entry.get("length", len(value)),
                "context": entry.get("context", ""),
            })
            
            if len(filtered) >= max_strings:
                break
        
        return filtered

    def _build_jar_prompt(
        self, jar_path: str, strings: List[Dict[str, Any]], total_strings: int, is_batch: bool = False
    ) -> str:
        """Build prompt for JAR file analysis."""
        header = f"JAR File: {os.path.basename(jar_path)}\nTotal strings: {total_strings}\nAnalyzed: {len(strings)}"
        
        lines = []
        for idx, item in enumerate(strings, 1):
            addr = item.get("address") or "?"
            sec = item.get("section") or "?"
            val = item.get("value") or ""
            context = item.get("context", "")
            
            line = f"{idx}. [class={addr}][file={sec}] {val}"
            if context:
                # Include truncated context for better analysis
                context_preview = context.replace('\n', ' ')[:100]
                line += f"\n   Context: {context_preview}"
            lines.append(line)
        
        batch_instruction = ""
        if is_batch:
            batch_instruction = "Note: This is a partial batch. Analyze independently."
        
        return (
            "You are a Java security analyst reviewing hardcoded strings from a decompiled JAR file.\n"
            f"{batch_instruction}\n"
            "Focus on:\n"
            "1. Hardcoded credentials (passwords, API keys, tokens, secrets)\n"
            "2. Database connection strings with embedded credentials\n"
            "3. Encryption keys or initialization vectors\n"
            "4. Hardcoded URLs with sensitive endpoints\n"
            "5. SQL queries that might be vulnerable\n"
            "6. Debug/admin backdoors\n"
            "7. Sensitive file paths or configuration\n\n"
            "IMPORTANT: Return the exact string values as they appear.\n"
            "Return strict JSON: {summary, risk_level (low/medium/high), "
            "suspicious_entries: [{value, category, reason, address, section, confidence (a number between 0.0 and 1.0)}]}\n"
            "The 'confidence' field MUST be a decimal number (e.g., 0.85), NOT a string like 'high'.\n\n"
            f"Context:\n{header}\n\nStrings:\n" + "\n".join(lines)
        )

    # ==================== Context-Aware Analysis (ReAct Mode) ====================

    async def _context_aware_analysis(
        self,
        jar_path: str,
        all_strings: List[Dict[str, Any]],
        already_found: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Phase 3: Context-aware analysis for strings that need code context.
        
        This phase looks for strings that:
        1. Match patterns that typically need context (e.g., reserved users, device accounts)
        2. Were not already flagged in Phase 1/2
        3. Could be backdoors or auth bypasses when seen in code context
        """
        try:
            context_provider = JarContextProvider(jar_path)
            
            if not context_provider.has_decompiler():
                logger.warning("[StringAudit] CFR decompiler not available, skipping context-aware analysis")
                logger.info("[StringAudit] To enable context analysis, install CFR: https://www.benf.org/other/cfr/")
                return []
            
            # Find strings that need context checking
            already_found_values = {e.get("value", "").lower() for e in already_found}
            needs_context = []
            
            for entry in all_strings:
                value = entry.get("value", "")
                if not value or value.lower() in already_found_values:
                    continue
                if self._needs_context_check(value):
                    needs_context.append(entry)
            
            if not needs_context:
                logger.info("[StringAudit] No strings require context analysis")
                return []
            
            logger.info(f"[StringAudit] Context analysis: {len(needs_context)} strings need code context")
            
            # Limit the number of context requests
            needs_context = needs_context[:self.MAX_CONTEXT_REQUESTS]
            
            # Get code context for each string
            items_with_context = []
            for entry in needs_context:
                value = entry.get("value", "")
                class_hint = entry.get("address", "").split(":")[0] if entry.get("address") else ""
                
                # Find which classes contain this string
                containing_classes = context_provider.find_classes_containing_string(value)
                
                if not containing_classes:
                    continue
                
                # Prefer the class mentioned in address if available
                target_class = containing_classes[0]
                if class_hint:
                    for c in containing_classes:
                        if class_hint in c:
                            target_class = c
                            break
                
                # Get code context
                code_context = context_provider.get_string_usage_context(value, target_class)
                
                if code_context and not code_context.startswith("["):
                    items_with_context.append({
                        "value": value,
                        "class_name": target_class,
                        "code_context": code_context[:3000]  # Limit context size
                    })
            
            if not items_with_context:
                logger.info("[StringAudit] No usable code context found")
                return []
            
            logger.info(f"[StringAudit] Analyzing {len(items_with_context)} strings with code context")
            
            # Send to LLM for context-aware analysis
            context_findings = await self._analyze_with_context(items_with_context)
            
            return context_findings
            
        except Exception as e:
            logger.error(f"[StringAudit] Context-aware analysis failed: {e}")
            return []

    async def _analyze_with_context(
        self, items_with_context: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Send strings with code context to LLM for analysis."""
        
        context_blocks = []
        for item in items_with_context:
            value = item.get("value", "")
            class_name = item.get("class_name", "")
            context = item.get("code_context", "")
            
            context_blocks.append(f"""
=== String: "{value}" ===
Class: {class_name}
Code Context:
```java
{context}
```
""")
        
        prompt = f"""You are a security analyst. Analyze these strings WITH their code context.

CRITICAL: Look for authentication bypass patterns, such as:
1. Strings used in if/else conditions that bypass normal authentication
2. Reserved/special usernames that trigger different authentication paths
3. Hardcoded usernames that validate against file-based passwords (backdoors)
4. Device/service accounts that bypass normal user authentication

For example, this is a BACKDOOR:
```java
if (username.equals("viptela-reserved-uc"))
    return validateVmanageReservedUser("/opt/web-app/etc/.vmanage_service_user.json", password, "upgradecoordinator");
```
This bypasses normal authentication for the username "viptela-reserved-uc".

Analyze each string and determine if it represents a security vulnerability.

Return JSON:
{{
    "findings": [
        {{
            "value": "exact string value",
            "is_vulnerability": true,
            "category": "backdoor_account|hardcoded_credential|auth_bypass|...",
            "reason": "Detailed explanation based on code context",
            "confidence": 0.95,
            "code_evidence": "The specific code pattern that proves this"
        }}
    ]
}}

Only include findings where is_vulnerability is true.
If none of the strings are vulnerabilities, return {{"findings": []}}.

Strings to analyze:
{"".join(context_blocks)}
"""
        
        try:
            response = self.model.chat(prompt=prompt)
            parsed = self._safe_json(response)
            
            if not parsed or "findings" not in parsed:
                return []
            
            findings = []
            for f in parsed["findings"]:
                if f.get("is_vulnerability", False):
                    # Convert to standard entry format
                    findings.append({
                        "value": f.get("value", ""),
                        "category": f.get("category", "context_discovered"),
                        "reason": f.get("reason", "") + f"\n\nCode Evidence: {f.get('code_evidence', '')}",
                        "address": "context_analysis",
                        "section": "decompiled",
                        "confidence": parse_confidence(f.get("confidence", 0.8)),
                        "discovery_method": "context_aware_analysis"
                    })
            
            return findings
            
        except Exception as e:
            logger.error(f"[StringAudit] Context analysis LLM call failed: {e}")
            return []


    async def _binary_context_aware_analysis(
        self,
        binary_path: str,
        all_strings: List[Dict[str, Any]],
        already_found: List[Dict[str, Any]],
        ida_version: str
    ) -> List[Dict[str, Any]]:
        """
        Phase 3: Binary context-aware analysis using IDA cross-references.
        
        This phase:
        1. Takes suspicious strings from Phase 1/2
        2. Uses IDA to find where these strings are referenced in code
        3. Gets decompiled code context
        4. Re-analyzes with LLM using code context
        
        Args:
            binary_path: Path to the binary file
            all_strings: All extracted strings
            already_found: Suspicious entries already found
            ida_version: IDA version to use (ida32/ida64)
            
        Returns:
            List of additional findings discovered through context analysis
        """
        try:
            # 1. 准备需要上下文分析的字符串
            # 优先分析需要上下文的模式（保留用户、设备账户等）
            already_found_values = {e.get("value", "").lower() for e in already_found}
            needs_context = []
            
            # 首先检查所有字符串中需要上下文的模式
            for entry in all_strings:
                value = entry.get("value", "")
                if not value or value.lower() in already_found_values:
                    continue
                if self._needs_context_check(value):
                    needs_context.append({
                        "value": value,
                        "address": entry.get("address", ""),
                        "vaddr": entry.get("vaddr", "")
                    })
            
            # 也为已发现的可疑字符串获取上下文（用于更精确的分析）
            suspicious_for_context = []
            for entry in already_found[:self.MAX_CONTEXT_REQUESTS // 2]:  # 取一半配额
                suspicious_for_context.append({
                    "value": entry.get("value", ""),
                    "address": entry.get("address", ""),
                    "vaddr": entry.get("vaddr", entry.get("address", ""))
                })
            
            # 合并需要上下文的字符串
            all_needs_context = needs_context[:self.MAX_CONTEXT_REQUESTS // 2] + suspicious_for_context
            
            if not all_needs_context:
                logger.info("[StringAudit] No strings require binary context analysis")
                return []
            
            logger.info(f"[StringAudit] Binary context analysis: {len(all_needs_context)} strings")
            
            # 2. 调用IDA服务获取字符串的交叉引用和代码上下文
            context_url = f"{self.ida_service_url}/string_context"
            context_result = await self.ida_toolkit.get_string_context(
                binary_path=binary_path,
                strings=all_needs_context,
                max_xrefs=5,  # 每个字符串最多5个交叉引用
                context_url=context_url
            )
            
            if context_result.get("status") != "success":
                logger.warning(f"[StringAudit] Binary context analysis failed: {context_result.get('message', 'Unknown error')}")
                return []
            
            raw_results = context_result.get("results", [])
            if not raw_results:
                logger.info("[StringAudit] No context results from IDA")
                return []
            
            # IDA 服务返回的结构: {"status": "success", "results": {"mode": "batch", "results": [...]}}
            # 需要提取嵌套的 results 字段
            if isinstance(raw_results, dict):
                # raw_results 是 {"mode": "batch", "binary": "...", "results": [...]}
                if "results" in raw_results:
                    results = raw_results.get("results", [])
                    if not isinstance(results, list):
                        logger.warning(f"[StringAudit] Nested results is not a list: {type(results)}")
                        return []
                else:
                    # 可能是旧格式或单个结果
                    logger.warning(f"[StringAudit] Dict without 'results' key, using as single item")
                    results = [raw_results]
            elif isinstance(raw_results, list):
                # 如果直接是列表，直接使用（兼容旧版本）
                results = raw_results
            else:
                logger.error(f"[StringAudit] Unexpected raw_results type: {type(raw_results)}")
                return []
            
            if not results:
                logger.info("[StringAudit] No results after parsing")
                return []
            
            logger.info(f"[StringAudit] Got context for {len(results)} strings")
            
            # 3. 构建带上下文的分析请求
            context_blocks = []
            for r in results:
                if not isinstance(r, dict):
                    logger.warning(f"[StringAudit] Skip invalid context item type: {type(r)}")
                    continue
                
                original_query = r.get("original_query", {}) if isinstance(r.get("original_query"), dict) else {}
                string_value = (
                    r.get("string_value")
                    or r.get("value")
                    or r.get("string")
                    or original_query.get("value")
                    or ""
                )
                
                contexts = r.get("contexts", []) if isinstance(r.get("contexts"), list) else []
                functions = r.get("functions", []) if isinstance(r.get("functions"), list) else []
                if not functions and contexts:
                    functions = [
                        {
                            "name": c.get("func_name", "unknown"),
                            "address": c.get("func_addr", ""),
                            "xref_address": c.get("xref_addr", ""),
                            "decompiled_code": c.get("decompiled") or "",
                            "disasm": c.get("disasm") or ""
                        }
                        for c in contexts
                        if isinstance(c, dict)
                    ]
                
                xref_count = r.get("xref_count", len(contexts) or len(functions))
                
                if not functions:
                    continue
                
                # 构建该字符串的上下文块
                block = f"\n### String: `{string_value}`\n"
                block += f"Cross-references: {xref_count}\n\n"
                
                for func in functions[:3]:  # 最多取3个函数
                    func_name = func.get("name", "unknown")
                    decompiled = func.get("decompiled_code", "") or func.get("disasm", "")
                    if decompiled:
                        # 截断过长的反编译代码
                        if len(decompiled) > 2000:
                            decompiled = decompiled[:2000] + "\n... [truncated]"
                        block += f"#### Function: `{func_name}`\n```c\n{decompiled}\n```\n\n"
                
                context_blocks.append(block)
            
            if not context_blocks:
                logger.info("[StringAudit] No usable context blocks")
                return []
            
            # 4. 使用LLM分析带上下文的字符串
            prompt = f"""You are analyzing hardcoded strings in a binary with their code context.
Based on the decompiled code, determine if any strings represent security vulnerabilities.

Focus on:
1. Hardcoded credentials (passwords, API keys, tokens)
2. Backdoor accounts (especially in authentication/login functions)
3. Debug/test credentials left in production
4. Hardcoded encryption keys
5. Suspicious authentication bypasses

Binary: {os.path.basename(binary_path)}

Return JSON only:
{{
    "findings": [
        {{
            "value": "the suspicious string",
            "category": "hardcoded_credential|backdoor|debug_credential|encryption_key|auth_bypass",
            "reason": "why this is a vulnerability based on code context",
            "code_evidence": "relevant code snippet showing the vulnerability",
            "function_name": "name of function where string is used",
            "is_vulnerability": true,
            "confidence": 0.85
        }}
    ]
}}

Rules:
- is_vulnerability must be true only if the code context clearly shows security risk
- confidence should be 0.7-0.95 based on code evidence clarity
- Include code_evidence showing how the string is used
- If string is used safely (e.g., just logging), mark is_vulnerability as false

Strings with code context:
{"".join(context_blocks)}
"""
            
            try:
                response = self.model.chat(prompt=prompt)
                parsed = self._safe_json(response)
                
                if not parsed or "findings" not in parsed:
                    return []
                
                findings = []
                for f in parsed["findings"]:
                    if f.get("is_vulnerability", False):
                        findings.append({
                            "value": f.get("value", ""),
                            "category": f.get("category", "context_discovered"),
                            "reason": f.get("reason", "") + f"\n\nCode Evidence: {f.get('code_evidence', '')}\nFunction: {f.get('function_name', '')}",
                            "address": "binary_context_analysis",
                            "section": "decompiled",
                            "confidence": parse_confidence(f.get("confidence", 0.8)),
                            "discovery_method": "binary_context_aware_analysis"
                        })
                
                return findings
                
            except Exception as e:
                logger.error(f"[StringAudit] Binary context analysis LLM call failed: {e}")
                return []
            
        except Exception as e:
            logger.error(f"[StringAudit] Binary context analysis failed: {e}", exc_info=True)
            return []

