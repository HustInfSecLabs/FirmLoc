from agent.base import Agent
from agent.parameter_agent import CWE_SENSITIVE_BINARIES, CWE_DESCRIPTIONS
from model.base import ChatModel
from pathlib import Path
from log import logger
from tools.binary_diff_detector import find_modified_binaries, format_diff_summary, get_modified_binaries_list
import json
import re
import tiktoken
import os
import subprocess
import stat

PROMPT_REPRODUCTION = """You are a security analyst who specializes in analyzing binary files that may have vulnerabilities based on the names of affected services/programs and their vulnerability types mentioned in CVE descriptions and other information.
You need to find relevant binary files that may have vulnerabilities in the executable binary list [directory] (extracted from the firmware directory) and CVE information [CVE details] of the {binary_filename} device provided below.

Strictly output **raw JSON only** in the following format (do NOT wrap with Markdown code fences):
{{
"status": "success" | "error",  // use "error" when unsure
"message": "Analysis description",
"suspicious_binaries": [
{{
"binary_name": "Binary file name xxx",
"binary_path": "Binary file path",
"reason": "Determine the reason why the file may have a vulnerability"
}},
{{
"binary_name": "Binary file name yyy",
"binary_path": "Binary file path",
"reason": "Determine the reason why the file may have a vulnerability"
}}
]
}}

Rules:
- suspicious_binaries can output up to 1, sorted by relevance (most suspicious first).
- If a suspicious binary cannot be determined, set status to "error" and return an empty suspicious_binaries array with a clear message.
- Do not include any extra text, Markdown, or explanations outside the JSON.

Example error message output:
{{
"status": "error",
"message": "According to CVE information, no relevant suspicious binary files were found in the provided directory",
"suspicious_binaries": []
}}

Now the following is a real application scenario. Please analyze the following information and output the analysis results strictly in accordance with the format requirements.

[CVE details]
{cve_details}
[CVE details end]

[directory]
{directory}
[directory end]
Please make sure that the file path really exists.
"""

PROMPT_DISCOVERY = """You are a security analyst specializing in vulnerability discovery. Your task is to identify binary files that are most likely to contain {cwe_type} vulnerabilities.

**Vulnerability Type Information:**
- CWE ID: {cwe_id}
- Description: {cwe_description}

**CWE-Specific Analysis Guidelines:**
{cwe_guidelines}

**Historical Reference CVEs (if available):**
{reference_cves}

**Target Device:** {binary_filename}

Your task: Analyze the executable binary list below and identify binaries that are most likely to contain {cwe_type} vulnerabilities.

Strictly output **raw JSON only** in the following format (do NOT wrap with Markdown code fences):
{{
"status": "success" | "error",
"message": "Analysis description",
"suspicious_binaries": [
{{
"binary_name": "Binary file name",
"binary_path": "Binary file path",
"reason": "Explain why this binary is likely to have {cwe_type} vulnerability",
"priority": "high|medium|low"
}}
]
}}

Rules:
- suspicious_binaries can output up to 5, sorted by priority (highest first).
- Focus on binaries that:
  * Handle external input (network, files, user input)
  * Match the vulnerability pattern for {cwe_id}
  * Are common targets for this vulnerability type
- If no suspicious binaries can be determined, set status to "error" with a clear message.
- Do not include any extra text, Markdown, or explanations outside the JSON.

[directory]
{directory}
[directory end]
Please make sure that the file path really exists.
"""

CWE_ANALYSIS_GUIDELINES = {
    "CWE-78": """
- Focus on binaries that execute shell commands (system(), popen(), exec*)
- Look for web servers (httpd, lighttpd, goahead, boa, mini_httpd, uhttpd)
- Look for CGI handlers and scripts processors
- Network services that parse user input and pass to system commands
- Configuration utilities that accept user parameters
""",
    "CWE-77": """
- Similar to CWE-78, focus on command execution
- Look for binaries using shell interpreters
- Configuration management tools
""",
    "CWE-120": """
- Focus on binaries handling buffer operations (strcpy, memcpy, sprintf)
- Network daemons (httpd, ftpd, telnetd, sshd)
- Protocol parsers (upnpd, dnsd, dhcpd)
- Firmware update handlers
""",
    "CWE-121": """
- Focus on binaries with local buffer operations
- Look for parsers and decoders
- Network services processing structured data
""",
    "CWE-122": """
- Focus on binaries with dynamic memory allocation
- Complex parsers (XML, JSON, config files)
- Media/file format handlers
""",
    "CWE-22": """
- Focus on file servers and upload handlers
- Web servers with file access functionality
- FTP servers (ftpd, vsftpd)
- File management utilities
""",
    "CWE-787": """
- Focus on array/buffer write operations
- Network packet handlers
- Protocol decoders
- Media file parsers
""",
    "CWE-125": """
- Focus on array/buffer read operations
- Data parsers and format handlers
- Network data processors
""",
    "CWE-416": """
- Focus on complex state management
- Session handlers
- Connection managers
- Resource cleanup code
""",
    "CWE-798": """
- Focus on authentication modules
- Login handlers
- Configuration files with embedded credentials
- Admin interfaces
""",
}
class BinaryFilterAgent(Agent):
    """translatedAgent"""
    
    def __init__(self, chat_model: ChatModel) -> None:
        super().__init__(chat_model)
        
    def _get_directory_structure(self, directory_path: str) -> str:
        try:
            result = subprocess.run(
                ['du','-ah', '.'],
                cwd=Path(directory_path),
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except Exception as e:
            raise RuntimeError(f"translateddu -ahtranslated: {str(e)}")
    def _is_ida_analysable(self, file_path: Path) -> bool:
        """
        translated IDA translated.
        translated(magic bytes)translated(ELF、PE、Mach-O、translated shebang translated),
        translated `file` translated(translated).
        """
        try:
            with open(file_path, 'rb') as f:
                header = f.read(8)
        except (OSError, ValueError):
            return False

        # ELF: 0x7f 'E' 'L' 'F'
        if header.startswith(b'\x7fELF'):
            return True
        # PE (Windows executable and DLL): 'MZ'
        if header.startswith(b'MZ'):
            return True
        # Mach-O magic numbers
        mach_magic = [b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe']
        if header[:4] in mach_magic:
            return True
        # Script with shebang
        if header.startswith(b'#!'):
            return True

        # Fallback: use `file` command if available to detect shared object / executable descriptions
        try:
            result = subprocess.run(['file', '-b', str(file_path)], capture_output=True, text=True, check=False)
            desc = result.stdout.lower()
            keywords = ['elf', 'pe32', 'ms-dos', 'mach-o', 'shared object', 'executable', 'dynamically linked']
            if any(k in desc for k in keywords):
                return True
        except Exception:
            pass

        return False

    def _get_executable_binaries(self, directory_path: str) -> str:
        """
        translated(translated IDA translated)
        
        translated,translated,translated.
        translated:
        1. translated(ELF/PE/Mach-Otranslated)
        2. translated,translated
        3. translated(translated .txt, .sh, .conf translated)
        """
        executable_files = []
        directory = Path(directory_path)
        
        excluded_extensions = {
            '.txt', '.md', '.conf', '.cfg', '.xml', '.json', '.yaml', '.yml',
            '.html', '.htm', '.css', '.js', '.log', '.ini', '.properties',
            '.sh', '.py', '.pl', '.rb', '.lua',  # translated
            '.list', '.control', '.pat',  # opkg translated
        }

        for root, _, files in os.walk(directory_path):
            for filename in files:
                file_path = Path(root) / filename
                
                file_ext = file_path.suffix.lower()
                if file_ext in excluded_extensions:
                    continue
                
                try:
                    stat_result = file_path.stat()
                except (OSError, ValueError):
                    continue

                if not stat.S_ISREG(stat_result.st_mode):
                    continue

                try:
                    is_analysable = self._is_ida_analysable(file_path)
                except Exception:
                    is_analysable = False
                
                has_exec_bit = bool(stat_result.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                
                if is_analysable or has_exec_bit:
                    try:
                        relative_path = file_path.relative_to(directory)
                    except ValueError:
                        relative_path = file_path
                    executable_files.append(str(relative_path))

        if not executable_files:
            return "translated."

        executable_files.sort()
        return "\n".join(executable_files)

    def _extract_json_block(self, response: str) -> str:
        """translated JSON translated,translated markdown translated JSON."""
        if not response:
            return ""

        json_match = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", response, re.IGNORECASE)
        if json_match:
            return json_match.group(1).strip()

        brace_match = re.search(r"({[\s\S]+})", response)
        if brace_match:
            return brace_match.group(1).strip()

        return ""

    def _normalize_process_result(self, process_result: dict) -> tuple:
        """
        translated,translated.
        translated (normalized_dict, warning_str|None)
        """
        if not isinstance(process_result, dict):
            return None, "translated JSON translated"

        status = process_result.get("status", "error")
        if status not in {"success", "error"}:
            status = "error"

        message = str(process_result.get("message", "")).strip()
        suspicious_list = process_result.get("suspicious_binaries", [])
        if not isinstance(suspicious_list, list):
            suspicious_list = []

        normalized_binaries = []
        for item in suspicious_list[:3]:
            if not isinstance(item, dict):
                continue
            binary_name = str(item.get("binary_name", "")).strip()
            binary_path = str(item.get("binary_path", "")).strip()
            reason = str(item.get("reason", "")).strip() or "translated"

            if not binary_name and binary_path:
                binary_name = Path(binary_path).name

            if not binary_name and not binary_path:
                continue

            normalized_binaries.append({
                "binary_name": binary_name,
                "binary_path": binary_path,
                "reason": reason
            })

        warning = None
        if status == "success" and not normalized_binaries:
            warning = "translated success translated,translated error"
            status = "error"
            if not message:
                message = warning

        normalized = {
            "status": status,
            "message": message or "translated",
            "suspicious_binaries": normalized_binaries
        }

        return normalized, warning

    def _build_retry_prompt(self, base_prompt: str, last_error: str) -> str:
        """translated,translated JSON."""
        retry_hint = (
            "\n\ntranslated JSON translated,translated: "
            f"{last_error}.translated JSON,translated status/message/suspicious_binaries,"
            "translated Markdown translated,translated status=\"error\" translated suspicious_binaries translated."
        )
        return base_prompt + retry_hint

    def _chat_and_parse_with_retry(self, prompt: str, max_attempts: int = 2) -> tuple:
        """translated,translated."""
        errors = []
        last_raw = ""

        for attempt in range(max_attempts):
            raw_response = self.chat_model.chat(prompt)
            last_raw = raw_response

            json_str = self._extract_json_block(raw_response)
            if not json_str:
                errors.append("translated JSON translated")
                prompt = self._build_retry_prompt(prompt, errors[-1])
                continue

            try:
                process_result = json.loads(json_str)
            except Exception as e:
                errors.append(f"JSON translated: {str(e)}")
                prompt = self._build_retry_prompt(prompt, errors[-1])
                continue

            normalized, warning = self._normalize_process_result(process_result)
            if normalized:
                has_binaries = bool(normalized.get("suspicious_binaries"))
                status_is_success = normalized.get("status") == "success"
                
                is_last_attempt = (attempt == max_attempts - 1)
                
                if has_binaries or status_is_success or is_last_attempt:
                    if warning:
                        normalized["message"] = f"{normalized.get('message', '')} | {warning}".strip(" |")
                    return normalized, raw_response
                
                if not has_binaries and not status_is_success:
                    error_msg = f"translated status=error translated.translated: {normalized.get('message', 'translated')}"
                    errors.append(error_msg)
                    logger.warning(f"translated {attempt + 1} translated: {error_msg},translated...")
                    
                    retry_hint = (
                        "\n\ntranslated."
                        "translated,"
                        "translated:"
                        "\n1. translated(translatedhttpd、cgi、admintranslated)"
                        "\n2. translated(translated/usr/sbin、/bin、/usr/bintranslated)"
                        "\n3. translated"
                        "\n\ntranslated,translated1translated."
                        "\ntranslatedJSONtranslated,statustranslated\"success\",translatedsuspicious_binariestranslated1translated."
                    )
                    prompt = prompt + retry_hint
                    continue

            errors.append(warning or "translated")
            prompt = self._build_retry_prompt(prompt, errors[-1])

        fallback_message = "; ".join(errors) if errors else "translated"
        return {
            "status": "error",
            "message": f"translated: {fallback_message}",
            "suspicious_binaries": []
        }, last_raw
    
    def _heuristic_filter_by_cwe(self, executable_binaries: str, cwe_id: str) -> list:
        """
        translatedCWEtranslated,translated
        """
        if not cwe_id or not executable_binaries:
            return []
        
        sensitive_keywords = CWE_SENSITIVE_BINARIES.get(cwe_id.upper(), [])
        if not sensitive_keywords:
            return []
        
        binaries = executable_binaries.strip().split('\n')
        scored_binaries = []
        
        for binary_path in binaries:
            binary_name = Path(binary_path).name.lower()
            score = 0
            matched_keywords = []
            
            for keyword in sensitive_keywords:
                if keyword.lower() in binary_name:
                    score += 2
                    matched_keywords.append(keyword)
                elif keyword.lower() in binary_path.lower():
                    score += 1
                    matched_keywords.append(keyword)
            
            if score > 0:
                scored_binaries.append({
                    "path": binary_path,
                    "name": Path(binary_path).name,
                    "score": score,
                    "keywords": matched_keywords
                })
        
        scored_binaries.sort(key=lambda x: x["score"], reverse=True)
        return scored_binaries[:10]  # translated10translated
    
    def _heuristic_filter_by_cve(self, executable_binaries: str, cve_details: str) -> list:
        """
        translatedCVEtranslated,translatedCVEtranslated/translated
        
        translatedCVEtranslated、translated,translated
        """
        if not cve_details or not executable_binaries:
            return []
        
        common_services = {
            "httpd": 15, "apache": 15, "nginx": 15, "lighttpd": 15, 
            "goahead": 15, "boa": 15, "uhttpd": 15, "mini_httpd": 15,
            "thttpd": 15, "mongoose": 15,
            "cgi": 12, "cgi-bin": 12, "php": 10, "fcgi": 10,
            "ftpd": 15, "vsftpd": 15, "proftpd": 15, "pure-ftpd": 15,
            "sshd": 15, "telnetd": 15, "dropbear": 15,
            "upnpd": 12, "miniupnpd": 12, "samba": 12, "smbd": 12,
            "dhcpd": 10, "dnsmasq": 10, "hostapd": 10,
            "busybox": 8, "login": 10, "admin": 10, "config": 8,
            "setup": 10, "upgrade": 10, "update": 10,
        }
        
        cve_lower = cve_details.lower()
        extracted_keywords = {}
        
        for keyword, weight in common_services.items():
            if keyword in cve_lower:
                extracted_keywords[keyword] = weight
        
        if not extracted_keywords:
            logger.warning("CVEtranslated,translated")
            extracted_keywords = {
                "httpd": 10, "cgi": 8, "ftpd": 8, "sshd": 8, 
                "telnetd": 8, "upnpd": 8, "admin": 6, "setup": 6
            }
        
        binaries = executable_binaries.strip().split('\n')
        scored_binaries = []
        
        for binary_path in binaries:
            binary_name = Path(binary_path).name.lower()
            binary_path_lower = binary_path.lower()
            score = 0
            matched_keywords = []
            
            for keyword, weight in extracted_keywords.items():
                if keyword in binary_name:
                    score += weight * 2  # translated
                    matched_keywords.append(keyword)
                elif keyword in binary_path_lower:
                    score += weight  # translated
                    matched_keywords.append(keyword)
            
            if score > 0:
                scored_binaries.append({
                    "path": binary_path,
                    "name": Path(binary_path).name,
                    "score": score,
                    "keywords": list(set(matched_keywords))  # translated
                })
        
        scored_binaries.sort(key=lambda x: x["score"], reverse=True)
        
        logger.info(f"CVEtranslated: translated {len(binaries)} translated {len(scored_binaries)} translated")
        return scored_binaries[:10]  # translated10translated
    
    def _format_reference_cves(self, cve_details: str, max_cves: int = 5) -> str:
        """translatedCVEtranslatedPrompt"""
        if not cve_details:
            return "No historical CVE references available."
        
        try:
            if isinstance(cve_details, str) and cve_details.strip().startswith('{'):
                cve_data = json.loads(cve_details)
                vulnerabilities = cve_data.get("vulnerabilities", [])[:max_cves]
                if vulnerabilities:
                    formatted = []
                    for vuln in vulnerabilities:
                        cve = vuln.get("cve", {})
                        cve_id = cve.get("id", "Unknown")
                        desc = ""
                        for d in cve.get("descriptions", []):
                            if d.get("lang") == "en":
                                desc = d.get("value", "")[:200]
                                break
                        formatted.append(f"- {cve_id}: {desc}...")
                    return "\n".join(formatted)
        except (json.JSONDecodeError, TypeError):
            pass
        
        if len(cve_details) > 500:
            return cve_details[:500] + "..."
        return cve_details
        
    def process(self, binary_filename: str, extracted_files_path: str, 
                cve_details: str = None, cwe_id: str = None, 
                work_mode: str = "reproduction", reference_cves: str = None,
                old_firmware_path: str = None, new_firmware_path: str = None,
                enable_diff_filter: bool = True) -> dict:
        """
        translated
        
        Args:
            binary_filename: translated/translated
            extracted_files_path: translated
            cve_details: CVEtranslated(translated)
            cwe_id: CWEtranslated(translated)
            work_mode: translated - "reproduction" translated "discovery"
            reference_cves: translatedCVEtranslated(translated)
            old_firmware_path: translated(translated)
            new_firmware_path: translated(translated)
            enable_diff_filter: translated(translatedTrue)
        """
        try:
            logger.info(f"BinaryFilterAgenttranslated (mode={work_mode}, cwe={cwe_id}, diff_filter={enable_diff_filter})...")
            
            all_executable_binaries = self._get_executable_binaries(extracted_files_path)
            logger.info(f"translated {len(all_executable_binaries.strip().split(chr(10)))} translated")
            
            filtered_binaries = all_executable_binaries
            diff_info = None
            
            if enable_diff_filter and old_firmware_path and new_firmware_path:
                logger.info("translated...")
                
                binary_paths = [line.strip() for line in all_executable_binaries.strip().split('\n') if line.strip()]
                
                diff_result = find_modified_binaries(old_firmware_path, new_firmware_path, binary_paths)
                diff_info = diff_result
                
                diff_summary = format_diff_summary(diff_result)
                logger.info(f"translated:\n{diff_summary}")
                
                modified_list = get_modified_binaries_list(diff_result, include_added=True, include_removed=False)
                
                if modified_list:
                    filtered_binaries = "\n".join(modified_list)
                    logger.info(f"translated {len(modified_list)} translated")
                else:
                    logger.warning("translated,translated")
                    filtered_binaries = all_executable_binaries
            else:
                if not enable_diff_filter:
                    logger.info("translated,translated")
                else:
                    logger.warning("translated,translated,translated")
            
            logger.info(f"translated {len(filtered_binaries.strip().split(chr(10)))} translated...")
            executable_binaries = filtered_binaries
            
            if work_mode == "discovery" and cwe_id:
                prompt = self._build_discovery_prompt(
                    binary_filename, executable_binaries, cwe_id, reference_cves
                )
            else:
                prompt = PROMPT_REPRODUCTION.format(
                    binary_filename=binary_filename,
                    directory=executable_binaries,
                    cve_details=cve_details or "No CVE details provided"
                )

            model_hint = getattr(self.chat_model, 'model_name', 'gpt-4o')
            enc = tiktoken.encoding_for_model(model_hint)
            token_ids = enc.encode(prompt)
            logger.debug(f"Prompt token translated: {len(token_ids)}")
            
            process_result, raw_response = self._chat_and_parse_with_retry(prompt, max_attempts=2)
            logger.debug(f"translated:{raw_response}")
            
            if diff_info:
                process_result["diff_statistics"] = {
                    "modified_count": len(diff_info.get("modified", [])),
                    "added_count": len(diff_info.get("added", [])),
                    "removed_count": len(diff_info.get("removed", [])),
                    "unchanged_count": len(diff_info.get("unchanged", []))
                }
            
            if process_result.get("status") == "error" or not process_result.get("suspicious_binaries"):
                if work_mode == "discovery" and cwe_id:
                    logger.info("LLMtranslated,translatedCWEtranslated...")
                    heuristic_results = self._heuristic_filter_by_cwe(executable_binaries, cwe_id)
                    if heuristic_results:
                        process_result = {
                            "status": "success",
                            "message": f"translatedCWE-{cwe_id}translated",
                            "suspicious_binaries": [
                                {
                                    "binary_name": r["name"],
                                    "binary_path": r["path"],
                                    "reason": f"translatedCWEtranslated: {', '.join(r['keywords'])}"
                                }
                                for r in heuristic_results[:5]
                            ]
                        }
                        logger.info(f"translated {len(process_result['suspicious_binaries'])} translated")
                elif work_mode == "reproduction" and cve_details:
                    logger.info("LLMtranslated,translatedCVEtranslated...")
                    heuristic_results = self._heuristic_filter_by_cve(executable_binaries, cve_details)
                    if heuristic_results:
                        process_result = {
                            "status": "success",
                            "message": f"translatedCVEtranslated",
                            "suspicious_binaries": [
                                {
                                    "binary_name": r["name"],
                                    "binary_path": r["path"],
                                    "reason": f"translatedCVEtranslated: {', '.join(r['keywords'])}"
                                }
                                for r in heuristic_results[:5]
                            ]
                        }
                        logger.info(f"translated {len(process_result['suspicious_binaries'])} translated")

            return process_result
                
        except Exception as e:
            logger.error(f"BinaryFilterAgenttranslated: {str(e)}")
            return {
                "status": "error",
                "message": f"process failed: {str(e)}",
                "suspicious_binaries": []
            }
    
    def _build_discovery_prompt(self, binary_filename: str, executable_binaries: str,
                                 cwe_id: str, reference_cves: str = None) -> str:
        """translatedPrompt"""
        cwe_id_upper = cwe_id.upper()
        cwe_description = CWE_DESCRIPTIONS.get(cwe_id_upper, "Unknown vulnerability type")
        cwe_guidelines = CWE_ANALYSIS_GUIDELINES.get(cwe_id_upper, "Focus on binaries that handle external input and match common vulnerability patterns.")
        
        formatted_refs = self._format_reference_cves(reference_cves) if reference_cves else "No historical CVE references available."
        
        heuristic_hints = self._heuristic_filter_by_cwe(executable_binaries, cwe_id)
        if heuristic_hints:
            hint_text = "\n**Pre-filtered candidates based on CWE patterns (for reference):**\n"
            for h in heuristic_hints[:5]:
                hint_text += f"- {h['name']} (matched: {', '.join(h['keywords'])})\n"
        else:
            hint_text = ""
        
        prompt = PROMPT_DISCOVERY.format(
            binary_filename=binary_filename,
            cwe_type=cwe_description,
            cwe_id=cwe_id_upper,
            cwe_description=cwe_description,
            cwe_guidelines=cwe_guidelines + hint_text,
            reference_cves=formatted_refs,
            directory=executable_binaries
        )
        
        return prompt