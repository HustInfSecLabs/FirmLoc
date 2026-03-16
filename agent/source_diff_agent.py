import os
import difflib
import json
from datetime import datetime
from utils import ConfigManager
from log import logger
from state import TaskStatusEnum
from agent.llm_diff import async_gpt_inference

SOURCE_DIFF_PROMPT = """
You are a security analyst. Your task is to analyze the following source code changes and determine if they fix a vulnerability or introduce one.

## Input
[File: {filename}]
[Location: Lines {line_range}]
[Before Change]
{code_before}

[After Change]
{code_after}

## Known Information
CVE Description: {cve_details}
CWE: {cwe}

## Output Format (JSON)
Answer only in JSON, with the following keys:
{{
  "is_security_relevant": "Yes/No",
  "vulnerability_type": "The type of vulnerability (e.g. Buffer Overflow)",
  "affected_function": "The function or method name affected by this change (if identifiable)",
  "analysis": "Detailed analysis of the change in Chinese (中文)",
  "confidence": "High/Medium/Low"
}}
"""

class SourceDiffAgent:
    def __init__(self, chat_id: str, task_name: str = "source_diff"):
        self.chat_id = chat_id
        self.task_name = task_name
        self.agent = "Source Diff Agent"
        self.tool_type = "text"
        self.tool_name = "SourceDiff"
        self.tool_status = "stop"
        self.status = TaskStatusEnum.NOT_STARTED

        self.output_dir = os.path.join("history", self.chat_id, "source_diff")
        os.makedirs(self.output_dir, exist_ok=True)

        self.state_file = os.path.join(self.output_dir, f"{self.task_name}_state.json")
        self.state = {
            "chat_id": self.chat_id,
            "tool": self.tool_name,
            "task_name": self.task_name,
            "status": str(self.status.name),
            "input": {},
            "result": None,
            "timestamp": str(datetime.now())
        }

    def _save_state(self):
        import json
        with open(self.state_file, 'w', encoding='utf-8') as f:
            json.dump(self.state, f, indent=4, ensure_ascii=False)

    def _extract_hunks(self, lines1, lines2, context=3):
        matcher = difflib.SequenceMatcher(None, lines1, lines2)
        hunks = []
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == 'equal':
                continue
            
            start1 = max(0, i1 - context)
            end1 = min(len(lines1), i2 + context)
            start2 = max(0, j1 - context)
            end2 = min(len(lines2), j2 + context)
            
            before = "".join(lines1[start1:end1])
            after = "".join(lines2[start2:end2])
            
            hunks.append({
                "type": tag,
                "before": before,
                "after": after,
                "line_range_before": f"{start1+1}-{end1}",
                "line_range_after": f"{start2+1}-{end2}",
                "changed_lines_before": f"{i1+1}-{i2}" if i2 > i1 else str(i1+1),
                "changed_lines_after": f"{j1+1}-{j2}" if j2 > j1 else str(j1+1)
            })
        return hunks

    async def execute(self, file1_path: str, file2_path: str, output_dir: str, cve_details: str = None, cwe: str = None, config: ConfigManager = None, send_message=None, on_status_update=None) -> dict:
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self.state_file = os.path.join(self.output_dir, f"{self.task_name}_state.json")
        self.status = TaskStatusEnum.IN_PROGRESS
        self.state["status"] = str(self.status.name)
        self.state["input"] = {
            "file1": file1_path,
            "file2": file2_path,
            "output_dir": self.output_dir
        }
        self._save_state()

        try:
            with open(file1_path, 'r', encoding='utf-8', errors='ignore') as f1:
                f1_lines = f1.readlines()
            with open(file2_path, 'r', encoding='utf-8', errors='ignore') as f2:
                f2_lines = f2.readlines()

            # 1. Generate HTML Diff
            diff = difflib.HtmlDiff().make_file(f1_lines, f2_lines, os.path.basename(file1_path), os.path.basename(file2_path))
            
            output_filename = f"{os.path.basename(file1_path)}_vs_{os.path.basename(file2_path)}.html"
            output_path = os.path.join(self.output_dir, output_filename)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(diff)

            # 2. Extract Hunks and Analyze
            hunks = self._extract_hunks(f1_lines, f2_lines)
            analysis_results = []
            
            if not hunks:
                logger.info("No differences found.")
            else:
                if send_message:
                    try:
                        msg = f"Found {len(hunks)} changed regions. Analyzing..."
                        logger.info(f"[{self.agent}] Sending message: {msg}")
                        await send_message(msg, "message", agent=self.agent)
                        logger.info(f"[{self.agent}] Message sent successfully")
                    except Exception as msg_err:
                        logger.error(f"[{self.agent}] Failed to send message: {msg_err}", exc_info=True)

                for i, hunk in enumerate(hunks):
                    line_range = f"{hunk['changed_lines_before']} -> {hunk['changed_lines_after']}"
                    prompt = SOURCE_DIFF_PROMPT.format(
                        filename=os.path.basename(file1_path),
                        line_range=line_range,
                        code_before=hunk['before'],
                        code_after=hunk['after'],
                        cve_details=cve_details or "Unknown",
                        cwe=cwe or "Unknown"
                    )
                    
                    try:
                        result_str = await async_gpt_inference(prompt, temperature=0)
                        # Try to parse JSON
                        try:
                            # Simple cleanup if needed
                            json_str = result_str
                            if "```json" in json_str:
                                json_str = json_str.split("```json")[1].split("```")[0]
                            elif "```" in json_str:
                                json_str = json_str.split("```")[1].split("```")[0]
                                
                            result_json = json.loads(json_str)
                            # Add location info to result
                            result_json["location"] = {
                                "hunk_index": i + 1,
                                "line_range_before": hunk['line_range_before'],
                                "line_range_after": hunk['line_range_after'],
                                "changed_lines_before": hunk['changed_lines_before'],
                                "changed_lines_after": hunk['changed_lines_after']
                            }
                            analysis_results.append(result_json)
                        except:
                            analysis_results.append({
                                "raw_output": result_str,
                                "location": {
                                    "hunk_index": i + 1,
                                    "line_range_before": hunk['line_range_before'],
                                    "line_range_after": hunk['line_range_after']
                                }
                            })
                            
                    except Exception as e:
                        logger.error(f"LLM analysis failed for hunk {i}: {e}")

            self.status = TaskStatusEnum.COMPLETED
            self.state["result"] = {
                "html_diff": output_path,
                "analysis": analysis_results
            }
            
            if on_status_update:
                on_status_update(None, self.tool_name, self.tool_status)

            tool_content = [
                {
                    "type": "text",
                    "content": f"Source code diff generated: {output_filename}\nAnalyzed {len(hunks)} changed regions."
                },
                {
                    "type": "file",
                    "link": f"/static/{os.path.relpath(output_path, start=os.path.dirname(output_dir))}" # Assuming static mapping
                }
            ]
            
            # Add analysis summary to content
            relevant_changes = [r for r in analysis_results if isinstance(r, dict) and r.get("is_security_relevant", "").lower() == "yes"]
            
            # Construct a more structured response for the frontend
            if relevant_changes:
                summary_text = "**安全相关变更:**\n\n"
                for i, r in enumerate(relevant_changes):
                    loc = r.get('location', {})
                    summary_text += f"**变更点 {loc.get('hunk_index', i+1)}:**\n"
                    summary_text += f"- **位置:** 第 {loc.get('changed_lines_before', 'N/A')} 行 → 第 {loc.get('changed_lines_after', 'N/A')} 行\n"
                    if r.get('affected_function'):
                        summary_text += f"- **影响函数:** `{r.get('affected_function')}`\n"
                    summary_text += f"- **漏洞类型:** {r.get('vulnerability_type', 'Unknown')}\n"
                    summary_text += f"- **置信度:** {r.get('confidence', 'Unknown')}\n"
                    summary_text += f"- **分析:** {r.get('analysis')}\n\n"
                
                tool_content.append({
                    "type": "text",
                    "content": summary_text
                })
            else:
                 tool_content.append({
                    "type": "text",
                    "content": "未检测到安全相关的变更。"
                })

            # Fix file link path for frontend
            # Assuming frontend expects /static/images/... or similar, but here we need to map correctly.
            # If main.py mounts /static/images to "images", we need to see where output_dir is relative to that.
            # output_dir is history/{chat_id}/source_diff
            # We might need to mount history folder in main.py or copy file to images/temp
            
            # For now, let's assume we copy the html to images/temp for easy access if history is not mounted
            temp_html_dir = os.path.join("images", "temp_diffs")
            os.makedirs(temp_html_dir, exist_ok=True)
            import shutil
            temp_html_path = os.path.join(temp_html_dir, output_filename)
            shutil.copy(output_path, temp_html_path)
            
            # Update link to point to the static mount
            # main.py: app.mount("/static/images", StaticFiles(directory="images"), name="static")
            web_link = f"/static/images/temp_diffs/{output_filename}"
            
            # Update the file item in tool_content
            tool_content[1] = {
                "type": "file", # Frontend might expect 'file' or 'link' or 'html'
                "link": web_link,
                "name": output_filename
            }

            if send_message:
                # Send the command execution message
                try:
                    cmd = f"diff {os.path.basename(file1_path)} {os.path.basename(file2_path)}"
                    logger.info(f"[{self.agent}] Sending command message: {cmd}")
                    logger.info(f"[{self.agent}] Tool content: {len(tool_content)} items")
                    logger.debug(f"[{self.agent}] Tool content detail: {json.dumps(tool_content, ensure_ascii=False, indent=2)}")
                    
                    await send_message(
                        cmd,
                        "command",
                        self.tool_type,
                        tool_content,
                        agent=self.agent,
                        tool=self.tool_name,
                        tool_status=self.tool_status
                    )
                    logger.info(f"[{self.agent}] Command message sent successfully")
                except Exception as send_err:
                    logger.error(f"[{self.agent}] Failed to send command message: {send_err}", exc_info=True)
                
                # Send a separate message with the analysis summary for better visibility in chat
                if relevant_changes:
                    try:
                        chat_summary = "### 安全分析结果\n\n"
                        for i, r in enumerate(relevant_changes):
                            loc = r.get('location', {})
                            chat_summary += f"#### 变更点 {loc.get('hunk_index', i+1)}\n"
                            chat_summary += f"- **位置**: 第 {loc.get('changed_lines_before', 'N/A')} 行 → 第 {loc.get('changed_lines_after', 'N/A')} 行\n"
                            if r.get('affected_function'):
                                chat_summary += f"- **影响函数**: `{r.get('affected_function')}`\n"
                            chat_summary += f"- **类型**: {r.get('vulnerability_type')}\n"
                            chat_summary += f"- **分析**: {r.get('analysis')}\n\n"
                        
                        logger.info(f"[{self.agent}] Sending analysis summary with {len(relevant_changes)} security-relevant changes")
                        await send_message(
                            chat_summary,
                            "message",
                            agent=self.agent
                        )
                        logger.info(f"[{self.agent}] Analysis summary sent successfully")
                    except Exception as summary_err:
                        logger.error(f"[{self.agent}] Failed to send analysis summary: {summary_err}", exc_info=True)

        except Exception as e:
            logger.error(f"Source diff failed: {e}")
            self.status = TaskStatusEnum.FAILED
            self.state["error"] = str(e)
        
        self.state["status"] = str(self.status.name)
        self._save_state()
        
        return self.state
