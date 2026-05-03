#!/usr/bin/env python3
import os
import re
import json
import difflib
import subprocess
import tiktoken
import asyncio
import requests
from pathlib import Path
import glob, time, random
from datetime import datetime
from typing import Any, Dict, List, Optional, Callable

import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.insert(0, project_root)

from model.agentmodel import AgentModel
from agent.data_flow_utils import format_key_param_data_flow, format_vuln_context
from agent.llm_stats import LLM_STATS as SHARED_LLM_STATS, count_tokens as shared_count_tokens
from config import config_manager
from log import logger, set_log_file


class LLMStats:
    def __init__(self):
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_calls = 0
        self.total_time = 0.0
        self.records = []  # translated

    def add_record(self, prompt_tokens, completion_tokens, cost_time, tag=""):
        self.total_prompt_tokens += prompt_tokens
        self.total_completion_tokens += completion_tokens
        self.total_calls += 1
        self.total_time += cost_time
        self.records.append({
            "tag": tag,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "time": round(cost_time, 4)
        })

    def summary(self):
        return {
            "total_calls": self.total_calls,
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "total_tokens": self.total_prompt_tokens + self.total_completion_tokens,
            "total_time_seconds": round(self.total_time, 4),
            "avg_time_per_call": round(self.total_time / self.total_calls, 4) if self.total_calls else 0
        }


LLM_STATS = LLMStats()


def count_tokens(text: str, model_name: str = "gpt-4o") -> int:
#def count_tokens(text: str, model_name: str = "MiniMax-M2.5") -> int:
#def count_tokens(text: str, model_name: str = "deepseek-chat") -> int:
#def count_tokens(text: str, model_name: str = "glm-5.1-fp8") -> int:
    try:
        enc = tiktoken.encoding_for_model(model_name)
    except KeyError:
        enc = tiktoken.get_encoding("cl100k_base")
    return len(enc.encode(text))


LLM_STATS = SHARED_LLM_STATS
count_tokens = shared_count_tokens


VULNERABILITY_SCENARIOS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'vulnerability_scenarios.json')

BASE_PROMPT = """Return ONLY a valid JSON object. DO NOT include any inner thoughts, reasoning steps, or extra commentary.
You are a security analyst. Your task is to judge whether the provided IDA-decompiled pseudo-C code represents a {$vulnerability_type$} vulnerability and whether the patch removes it.
Focus on the information in CVE_DESCRIPTION.
Scenario:
   - "Yes" if the C-like pseudocode Before Code Change LIKELY contains the vulnerability scenario described in {$vulnerability_type$}.
   - Include partial matches: if the code shows dangerous operations (like unsafe copy, command execution, buffer write) that COULD match the scenario, mark as "Yes".
   - This decision is based ONLY on the [C-like pseudocode Before Code Change]. Do NOT use post-patch mismatch to change it.
   - Even if parameter names or exact patterns don't match, if the code pattern is semantically similar to the scenario, mark as "Yes".

patch_effective:
   - "Yes" only if the C-like pseudocode After Code Change removes the vulnerability scenario in the corresponding vulnerable function.
   - "No" otherwise.

The final output fields MUST be derived STRICTLY as follows:
- "scenario_match" = scenario_exists
- "property_match" = patch_effective
- "Scenario_match & Property_match" = "Yes"
    ONLY IF scenario_exists == "Yes" AND patch_effective == "Yes"
  OTHERWISE it MUST be "No".

{$vulnerability_type$} Scenario & Property

Scenario (Yes/No):
{$scenario$}

Property (Yes/No):
{$property$}

## INPUT FORMAT
[C-like pseudocode Before Code Change]
{filea}
[filea end]

[C-like pseudocode After Code Change]
{fileb}
[fileb end]

## Output FORMAT(strict JSON)

Answer only in JSON, with four keys:

{
  "scenario_match": "Yes/No",
  "property_match": "Yes/No",
  "Scenario_match & Property_match": "Yes/No",
  "reason": [""]
}

## Known Information
CVE_DESCRIPTION: {$cve_details$}

translated:

[filea]
{$filea$}
[filea end]

[fileb]
{$fileb$}
[fileb end]


[result]
{$result$}
[result end]

"""

DISCOVERY_PROMPT = """Return ONLY a valid JSON object. DO NOT include any inner thoughts, reasoning steps, or extra commentary.
You are a security analyst specializing in vulnerability discovery. Your task is to analyze the provided IDA-decompiled pseudo-C code changes and identify potential {$vulnerability_type$} vulnerabilities.

**Vulnerability Type Information:**
- CWE ID: {$cwe_id$}
- Description: {$vulnerability_type$}

{$vulnerability_type$} Scenario & Property

Scenario (identifying potential vulnerability):
{$scenario$}

Property (security-relevant code patterns):
{$property$}

## INPUT FORMAT
[C-like pseudocode Version A (older/potentially vulnerable)]
{filea}
[filea end]

[C-like pseudocode Version B (newer/potentially patched)]
{fileb}
[fileb end]

## Analysis Guidelines for Vulnerability Discovery:
1. Focus on code changes that affect security-relevant operations
2. Look for patterns typical of {$vulnerability_type$} vulnerabilities
3. Identify if the changes introduce, fix, or are unrelated to security issues
4. Consider the context and data flow of the modified code

## Output FORMAT (strict JSON)

Answer only in JSON:

{{
  "vulnerability_found": "Yes/No",
  "scenario_match": "Yes/No",
  "property_match": "Yes/No",
  "vulnerability_type": "{$cwe_id$}",
  "severity": "High/Medium/Low/None",
  "vulnerable_code_location": "Description of where the vulnerability exists",
  "vulnerability_details": {{
    "root_cause": "Explain the root cause of the vulnerability",
    "attack_vector": "How could this be exploited",
    "impact": "What is the potential impact"
  }},
  "fix_analysis": {{
    "is_fixed": "Yes/No/Partial",
    "fix_description": "How the newer version addresses the issue"
  }},
  "reason": ["Detailed reasoning for the analysis"]
}}

translated:

[filea]
{$filea$}
[filea end]

[fileb]
{$fileb$}
[fileb end]

[result]
{$result$}
[result end]

"""

DEFAULT_DANGER_APIS = [
    "strcpy", "strncpy", "memcpy", "strcat", "sprintf", "snprintf", "gets",
    "system", "popen", "exec", "execve", "execl", "exece", "malloc", "free",
    "read", "write", "recv", "send", "socket", "bind", "accept", "strlcpy",
    "strncat"
]

DEFAULT_SLICE_BEFORE = 60
DEFAULT_SLICE_AFTER = 60

# ================== Ablation / Strategy Switch ==================
# Strategy meanings (for ablation studies):
# 1) Directly rank all changed functions to Top-20 CVE root candidates (zero-shot style); no tournament.
# 2) Scenario+Property stage-1 for all functions, then rank Scenario=Yes functions to Top-20; no tournament.
# 3) Stage-1 then ReAct for Scenario=Yes; rank (scenario_match=Yes & vulnerability_found=Yes) to Top-20; no tournament.
# 4) Full pipeline: Stage-1 then ReAct for Scenario=Yes; then tournament over (scenario_match=Yes & vulnerability_found=Yes & is_cve_root_function=Yes).
DEFAULT_ABLATION_STRATEGY = int(os.environ.get("VULN_ABLATION_STRATEGY", "4") or "4")
DEFAULT_LLM_CONFIG_KEY = config_manager.resolve_llm_key()

GENERATE_SCENARIO_PROMPT = """You are a security expert specializing in vulnerability classification and patch-based analysis.

Your task is to generate a high-quality description of a given CWE type in two fields:

1. "scenario": Describe the typical conditions under which this vulnerability occurs.
   - Explain the insecure pattern.
   - Identify the untrusted sources involved.
   - Identify the dangerous sinks, operations, or code patterns.
   - The description must be generalizable, not tied to any specific product, library, or platform.
   - Do NOT create a rigid rule. Instead, describe common indicators that the vulnerability is present.

2. "property": Describe how a patch generally mitigates this CWE.
   - Explain what types of code changes would actually eliminate or reduce the vulnerability.
   - Mention common patterns of correct fixes (validation, canonicalization, bounds checks, safe APIs, argument separation, etc.).
   - Clarify what kinds of changes do *not* qualify as a real fix (e.g., cosmetic changes, logging, reordering, length checks without logic correction).
   - The description should allow evaluation of whether a patch removes the vulnerability.

The style should match the following characteristics:
- Professional but not overly formal.
- Descriptive, not rigid or rule-based.
- Focused on code behavior, inputs, and mitigation logic.
- Similar in tone to descriptions such as:
  “The function calls a command execution API with arguments influenced by untrusted input…”
  “The patch removes injection risk by replacing unsafe APIs or adding strict validation…”

Please provide your response in JSON format with the following structure:
{{
  "scenario": "[Your scenario description]",
  "property": "[Your property description]"
}}
"""

SUMMARY_PROMPT = """
translated.
translated,translated.
translated:
Overview Summary(translated)
translated(translated CVE)
translated(SIGSEGV / heap-buffer-overflow / double free)
translated(instruction pointer / source code translated)
translated(call stack)

Root Cause Explanation(translated)
translated:
for example：The root cause is an incorrect header length value extracted from the malformed input. This length is used as the copy size in memcpy at foo.c:214, leading to heap buffer overflow.
translated:translated(X)、translated(sink)translated、translated、translated


[translated]
{$result$}
[translated end]

"""

TOP_3_SUMMARY_PROMPT = """translated,translated top-3 translated.

translated(translated):

- CVE translated: [translated]
- CWE translated: {cwe}
- translated: {global_confidence}%


### Rank 1: {rank1_name} (Primary)
- **translated**: {rank1_score}
- **translated**: {rank1_role}
- **translated**: {rank1_location}
- **translated**: {rank1_flow}
- **translated**: {rank1_reason}

### Rank 2: {rank2_name}
- **translated**: {rank2_score}
- **translated**: {rank2_role}
- **translated**: {rank2_location}
- **translated**: {rank2_flow}
- **translated**: {rank2_reason}

### Rank 3: {rank3_name}
- **translated**: {rank3_score}
- **translated**: {rank3_role}
- **translated**: {rank3_location}
- **translated**: {rank3_flow}
- **translated**: {rank3_reason}

{selection_reason}
"""


def format_top3_summary(tournament_result: Dict[str, Any], cve_number: str = "", react_analysis: Optional[Dict[str, Any]] = None) -> str:
    """
    Generate a concise summary of top-3 candidates from global attribution tournament,
    enriched with ReAct analysis evidence.

    Args:
        tournament_result: Dict containing tournament analysis with ranked_candidates
        cve_number: CVE identifier (e.g., "CVE-2024-57011")
        react_analysis: Optional dict with ReAct evidence keyed by function name
                       {
                           "sub_459BF0": {
                               "evidence": {...},
                               "vulnerability_details": {...},
                               "reason": [...]
                           },
                           ...
                       }

    Returns:
        Formatted summary string with top-3 functions and their detailed analysis
    """
    ranked = tournament_result.get("ranked_candidates", [])
    if not ranked or len(ranked) == 0:
        return "No ranked candidates available."

    # Extract top 3
    top_candidates = ranked[:3]
    react_analysis = react_analysis or {}

    # Build candidate info with evidence
    cand_infos = []
    for idx, cand in enumerate(top_candidates, 1):
        func_name = cand.get("function_name", "Unknown")
        score = cand.get("relevance_score", 0)
        role = cand.get("attack_chain_role", "Unknown")
        why = cand.get("why", "No explanation available")
        confidence = cand.get("confidence", 0)

        # Fetch ReAct evidence if available
        react_data = react_analysis.get(func_name, {})
        evidence = react_data.get("evidence", {})
        vuln_details = react_data.get("vulnerability_details", {})
        reason_points = react_data.get("reason", [])

        cand_infos.append({
            "rank": idx,
            "name": func_name,
            "score": score,
            "role": role,
            "why": why,
            "confidence": confidence,
            "data_flow": evidence.get("data_flow_trace", ""),
            "dangerous_ops": evidence.get("dangerous_operations", ""),
            "input_sources": evidence.get("input_sources", ""),
            "root_cause": vuln_details.get("root_cause", ""),
            "attack_vector": vuln_details.get("attack_vector", ""),
            "impact": vuln_details.get("impact", ""),
            "reason_points": reason_points,
        })

    # Get CVE and CWE info
    cwe = tournament_result.get("cwe", "Unknown")
    global_conf = tournament_result.get("global_confidence", 0)
    selection_reason = tournament_result.get("selection_reason", "")
    primary_func = tournament_result.get("primary_cve_root_function", "Unknown")

    # Format output
    output = []
    output.append("# translated(Top 3 translated)")
    output.append("")

    # CVE Section
    output.append("## 📋 translated")
    output.append(f"- **CVE translated**: {cve_number or 'TBD'}")
    output.append(f"- **CWE translated**: {cwe}")
    output.append(f"- **translated**: {global_conf}%")
    output.append(f"- **Primary translated**: {primary_func}")
    output.append("")

    # Top 3 Functions Section with detailed evidence
    output.append("## 🎯 translated(Rank Top 3)")
    output.append("")

    for info in cand_infos:
        verdict = "🔴 Primary" if info["rank"] == 1 else "🟡 Candidate"
        output.append(f"### Rank {info['rank']}: {info['name']} {verdict}")
        output.append("")

        # Basic metrics
        output.append("#### translated")
        output.append(f"- **translated**: {info['score']}/100")
        output.append(f"- **translated**: {info['confidence']}%")
        output.append(f"- **translated**: {info['role']}")
        output.append("")

        # Tournament analysis
        output.append("#### translated")
        output.append(f"- **translated**: {info['why']}")
        output.append("")

        # Evidence section (if available from ReAct)
        if info["data_flow"] or info["dangerous_ops"] or info["input_sources"]:
            output.append("#### 📊 translated")
            if info["data_flow"]:
                output.append(f"- **translated**: `{info['data_flow']}`")
            if info["dangerous_ops"]:
                output.append(f"- **translated**: `{info['dangerous_ops']}`")
            if info["input_sources"]:
                output.append(f"- **translated**: {info['input_sources']}")
            output.append("")

        # Vulnerability details section
        if info["root_cause"] or info["attack_vector"] or info["impact"]:
            output.append("#### 🔍 translated")
            if info["root_cause"]:
                output.append(f"- **translated**: {info['root_cause']}")
            if info["attack_vector"]:
                output.append(f"- **translated**: {info['attack_vector']}")
            if info["impact"]:
                output.append(f"- **translated**: {info['impact']}")
            output.append("")

        # Reasoning points
        if info["reason_points"]:
            output.append("#### 💡 translated")
            for idx, point in enumerate(info["reason_points"], 1):
                output.append(f"{idx}. {point}")
            output.append("")

    # Selection Reason
    output.append("## 📌 translated")
    output.append(f"{selection_reason}")
    output.append("")

    # Candidate Summary
    output.append("## 📊 translated")
    output.append(f"- **Primary CVE Root Function**: {primary_func}")
    output.append(f"- **translated**: {tournament_result.get('candidate_count', 0)}")
    output.append(f"- **translated**: {tournament_result.get('status', 'Unknown')}")
    output.append(f"- **translated**: translated + ReAct translated")

    return "\n".join(output)


def extract_react_evidence_by_function(results: str) -> Dict[str, Dict[str, Any]]:
    """
    Extract ReAct analysis evidence from analysis results by function name.

    Args:
        results: Analysis results string (translated JSON translated)

    Returns:
        Dict mapping function_name -> {evidence, vulnerability_details, reason, ...}
    """
    react_data = {}

    # Try to parse as JSON first (if entire content is JSON)
    try:
        content = json.loads(results)
        if isinstance(content, dict):
            # Handle nested structure
            for key, val in content.items():
                if isinstance(val, dict) and "evidence" in val:
                    func_name = val.get("function_name") or key
                    react_data[func_name] = val
    except (json.JSONDecodeError, ValueError):
        # Fall back to regex extraction
        pattern = r"=== ([\w]+)\.c vs [\w\.]+\s*\(ReActtranslated\)\s*===\s*(\{[^}]*(?:\{[^}]*\}[^}]*)*\})"
        matches = re.finditer(pattern, results, re.DOTALL)

        for match in matches:
            func_name = match.group(1)
            json_str = match.group(2)
            try:
                data = json.loads(json_str)
                react_data[func_name] = data
            except json.JSONDecodeError:
                pass

    return react_data


def format_top3_summary_from_file(tournament_json_path: str, results_file: str = "", cve_number: str = "") -> str:
    """
    Complete workflow: load tournament JSON, extract ReAct evidence, and generate summary.

    Args:
        tournament_json_path: Path to global_attribution_tournament.json
        results_file: Path to analysis results file (for extracting ReAct evidence)
        cve_number: CVE identifier

    Returns:
        Formatted summary string
    """
    # Load tournament result
    try:
        with open(tournament_json_path, 'r', encoding='utf-8') as f:
            tournament_result = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load tournament JSON: {e}")
        return f"Error loading tournament result: {str(e)}"

    # Extract ReAct evidence if results file provided
    react_analysis = {}
    if results_file and os.path.exists(results_file):
        try:
            with open(results_file, 'r', encoding='utf-8') as f:
                results_content = f.read()
            react_analysis = extract_react_evidence_by_function(results_content)
        except Exception as e:
            logger.warning(f"Failed to extract ReAct evidence: {e}")

    return format_top3_summary(tournament_result, cve_number, react_analysis)


async def async_gpt_inference(
    prompt: str,
    temperature: float = 0,
    max_tokens: int = 4096,
    default_system_prompt: str = "You are a helpful assistant.",
    tag: str = "",
    model_name: str = DEFAULT_LLM_CONFIG_KEY
) -> str:
    """translatedgpt_inferencetranslated,translated"""
    """
    translated LLM translated + token & translated
    """
    loop = asyncio.get_running_loop()
    start_time = time.time()
    try:
        result = await loop.run_in_executor(
            None,
            lambda: gpt_inference(
                prompt=prompt,
                temperature=temperature,
                default_system_prompt=default_system_prompt,
                model_name=model_name
            )
        )
    except asyncio.CancelledError:
        logger.warning("translated")
        raise
    except Exception as e:
        logger.error(f"translated: {e}")
        return f"translated: {str(e)}"
    
    usage = None
    if isinstance(result, tuple) and len(result) == 2:
        final_result, usage = result
    elif isinstance(result, str):
        final_result = result
    else:
        final_result = str(result)

    end_time = time.time()
    cost_time = end_time - start_time

    prompt_tokens = 0
    completion_tokens = 0
    if usage:
        prompt_tokens = int(getattr(usage, "prompt_tokens", 0) or 0)
        completion_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
    else:
        logger.warning(f"[LLM] tag={tag} missing real usage; exact token accounting skipped")

    if usage:
        LLM_STATS.add_record(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cost_time=cost_time,
            tag=tag,
            model_name=model_name
        )

    logger.info(
        f"[LLM] tag={tag} | "
        f"model={model_name} | "
        f"prompt_tokens={prompt_tokens}, "
        f"completion_tokens={completion_tokens}, "
        f"time={cost_time:.2f}s"
    )

    return final_result

def gpt_inference(
    prompt: str = None,
    temperature: int = 0,
    default_system_prompt: str = None,
    history: list = None,
    model_name: str = DEFAULT_LLM_CONFIG_KEY
):
    try:
        llm_diff_agent = AgentModel(model=model_name)
        
        system_prompt = "You are a helpful security assistant." if default_system_prompt == None else default_system_prompt
        messages = [{"role": "system", "content": system_prompt}]
        history = history or []
        for his in history:
            if isinstance(his, tuple) and len(his) == 2:
                q, a = his
                messages.append({"role": "user", "content": q})
                messages.append({"role": "assistant", "content": a})
            else:
                logger.warning(f"translated: {his}")
        messages.append({"role": "user", "content": prompt})
        completion = llm_diff_agent.create_completion(messages)
        result = AgentModel.extract_text(completion)

        return result, AgentModel.extract_usage(completion)
    except Exception as e:
        logger.error(f"translated: {e}")
        return f"translated: {str(e)}"

GLOBAL_ATTRIBUTION_TOURNAMENT_PROMPT = """You are the final cross-function adjudicator for a single CVE.

Your job is NOT to judge each function independently. Your job is to compare the candidate functions against each other, decide whether a unique primary CVE root function exists, and ALWAYS produce a full relevance ranking over all candidates.

Rules:
- Select a unique `primary_cve_root_function` ONLY if the evidence supports a clear winner. Otherwise set `primary_cve_root_function` and `primary_post_function` to null.
- A function may be vulnerable yet still NOT be the primary CVE root function.
- The `Primary` function MUST be the unique function that actually carries the bug and directly performs the dangerous memory write / triggering operation.
- Prefer the function whose own code and local semantics most directly implement the vulnerable behavior described in the CVE.
- Prefer the actual vulnerable sink / bug carrier over a page handler, request entry point, dispatcher, wrapper, caller, passthrough helper, or downstream consequence.
- If attacker input reaches a vulnerable callee and the actual bounds-check failure or dangerous write happens inside that callee, the callee is `Primary`, not the caller.
- If multiple candidates look related, reject the less direct ones as `intermediate`, `helper`, or `downstream manifestation`.
- Use comparative reasoning across candidates. Do NOT evaluate candidates in isolation.
- The ranked list MUST be ordered by strict relevance to the CURRENT CVE description, not by generic dangerousness alone.
- `relevance_score` means how strongly the function matches the CURRENT CVE description and serves as the most relevant candidate for THIS CVE compared with the other candidates.
- Generic use of a dangerous API is NOT sufficient for a high `relevance_score` if the attacker-controlled path or the CVE-described behavior is weaker than another candidate.
- If a valid `primary_cve_root_function` is selected, then `ranked_candidates[0]` MUST be that same function and MUST have verdict `Primary`.
- `ranked_candidates` MUST include EVERY function from `Candidates` exactly once. Do NOT return only top-k candidates. Do NOT omit any candidate.
- Do NOT mention any function outside the provided `Candidates` list.
- Keep output concise to fit the response budget: limit each `why` to <= 12 words for ranks > 5, and <= 20 words for ranks 1-5.

Selection priority:
1. Actual vulnerable sink / bug carrier where the dangerous write or bounds-check failure occurs
2. Strongest code-level evidence that removing or fixing this function would remove the CVE
3. Most direct attacker-controlled data flow into that vulnerable sink
4. Best semantic match to the CVE-described vulnerable behavior
5. Reject functions that merely prepare, forward, store, retrieve, dispatch, or display data unless they themselves perform the decisive vulnerable operation
6. When ranking candidates, prefer the function whose own code most specifically matches the CVE-described exploit path, trigger condition, and vulnerable behavior

CVE Description:
{cve_description}

CWE:
{cwe_id}

Candidates:
{candidate_block}

Output ONLY valid JSON in this exact format:
{{
  "primary_cve_root_function": "function name from candidates" or null,
  "primary_post_function": "paired post-patch function name from candidates" or null,
  "selection_reason": "Why this function wins over the other candidates",
  "global_confidence": <integer 0-100>,
  "ranked_candidates": [
    {{
      "rank": <integer starting from 1>,
      "function_name": "candidate function name",
      "post_function_name": "paired post-patch function name",
      "verdict": "Primary" or "Rejected" or "Candidate",
      "attack_chain_role": "entry point" or "intermediate" or "helper" or "downstream manifestation",
      "relevance_score": <integer 0-100>,
      "why": "Comparative reason for this verdict and this relevance rank relative to the other candidates",
      "confidence": <integer 0-100>
    }}
  ]
}}"""

GLOBAL_ATTRIBUTION_TOURNAMENT_TOPK_PROMPT = """You are the final cross-function adjudicator for a single CVE.

Your job is NOT to judge each function independently. Your job is to compare ALL candidate functions against each other and produce ONLY the top-{top_k} most CVE-relevant candidates (ordered best to worst).

Rules:
- Consider ALL candidates during comparison; do NOT ignore candidates outside the returned top-{top_k}.
- Select a unique `primary_cve_root_function` ONLY if the evidence supports a clear winner. Otherwise set `primary_cve_root_function` and `primary_post_function` to null.
- A function may be vulnerable yet still NOT be the primary CVE root function.
- The `Primary` function MUST be the unique function that actually carries the bug and directly performs the dangerous memory write / triggering operation described by THIS CVE.
- Prefer the actual vulnerable sink / bug carrier over a handler/dispatcher/wrapper/caller/passthrough helper.
- The ranked list MUST be ordered by strict relevance to the CURRENT CVE description, not by generic dangerousness alone.
- Generic use of a dangerous API is NOT sufficient for a high relevance score.
- If a valid `primary_cve_root_function` is selected, then `ranked_candidates[0]` MUST be that same function and MUST have verdict `Primary`.
- `ranked_candidates` MUST include EXACTLY {top_k} unique items (or all candidates if fewer than {top_k} total).
- Do NOT mention any function outside the provided `Candidates` list.
- Each `why` must be 1-2 sentences and should mention at least one concrete sink and one concrete input/source (if available).

CVE Description:
{cve_description}

CWE:
{cwe_id}

Candidates:
{candidate_block}

Output ONLY valid JSON in this exact format:
{{
  "primary_cve_root_function": "function name from candidates" or null,
  "primary_post_function": "paired post-patch function name from candidates" or null,
  "selection_reason": "Why the top-ranked candidate(s) best match this CVE",
  "global_confidence": <integer 0-100>,
  "ranked_candidates": [
    {{
      "rank": <integer starting from 1>,
      "function_name": "candidate function name",
      "post_function_name": "paired post-patch function name",
      "verdict": "Primary" or "Rejected" or "Candidate",
      "attack_chain_role": "entry point" or "intermediate" or "helper" or "downstream manifestation",
      "relevance_score": <integer 0-100>,
      "why": "Comparative reason for this rank",
      "confidence": <integer 0-100>
    }}
  ]
}}"""

def _build_compact_topk_prompt(
    cve_details: str,
    cwe: str,
    candidates: List[Dict[str, Any]],
    top_k: int,
) -> str:
    """
    Very small schema to get a stable top-k permutation (names + scores).
    This avoids long JSON that often causes truncation/duplication.
    """
    packed = _compact_candidates_for_tournament_prompt(candidates)
    candidate_block = json.dumps(packed, ensure_ascii=False, separators=(",", ":"))
    expected = min(max(1, int(top_k)), len(candidates))
    return f"""Return ONLY the top-{expected} most CVE-relevant candidates from the list.

Hard requirements:
- ranked_function_names MUST contain EXACTLY {expected} unique function names from Candidates.
- relevance_scores MUST be the same length as ranked_function_names; each score is 0-100.
- Order MUST be strict relevance to the CURRENT CVE description (not generic dangerousness).
- If you can justify a unique primary root function, set primary_cve_root_function accordingly; otherwise null.
- If primary is selected, it MUST be the first in ranked_function_names.

CVE Description:
{cve_details or "No CVE description provided."}

CWE:
{cwe or "Unknown"}

Candidates (compact fields):
{candidate_block}

Output ONLY valid JSON:
{{
  "primary_cve_root_function": <string or null>,
  "primary_post_function": <string or null>,
  "selection_reason": <string>,
  "global_confidence": <int 0-100>,
  "ranked_function_names": [<string>, ...],
  "relevance_scores": [<int>, ...]
}}"""


def _parse_compact_topk(
    payload: Any,
    candidates: List[Dict[str, Any]],
    top_k: int,
) -> Optional[Dict[str, Any]]:
    if not isinstance(payload, dict):
        return None
    ranked_names = payload.get("ranked_function_names")
    scores = payload.get("relevance_scores")
    if not isinstance(ranked_names, list) or not isinstance(scores, list):
        return None
    if len(ranked_names) != len(scores):
        return None
    expected = min(max(1, int(top_k)), len(candidates))
    if len(ranked_names) != expected:
        return None
    if len(set(ranked_names)) != len(ranked_names):
        return None

    candidate_map = {c["function_name"]: c for c in candidates}
    candidate_set = set(candidate_map.keys())
    if any((not isinstance(n, str)) or (n not in candidate_set) for n in ranked_names):
        return None

    primary = payload.get("primary_cve_root_function")
    if primary not in candidate_set:
        primary = None
    if primary and ranked_names and ranked_names[0] != primary:
        return None

    ranked_candidates: List[Dict[str, Any]] = []
    for idx, (name, score) in enumerate(zip(ranked_names, scores), 1):
        cand = candidate_map[name]
        ranked_candidates.append({
            "rank": idx,
            "function_name": name,
            "post_function_name": cand.get("post_function_name"),
            "verdict": "Primary" if primary and name == primary else "Candidate",
            "attack_chain_role": (cand.get("per_function_attribution") or {}).get("attack_chain_role", "Unknown"),
            "relevance_score": _safe_int(score, 0),
            "why": "",
            "confidence": _safe_int((cand.get("per_function_attribution") or {}).get("confidence"), 0),
        })

    return {
        "primary_cve_root_function": primary,
        "primary_post_function": payload.get("primary_post_function") if primary else None,
        "selection_reason": payload.get("selection_reason", ""),
        "global_confidence": _safe_int(payload.get("global_confidence"), 0),
        "ranked_candidates": ranked_candidates,
    }


def _build_topk_details_prompt(
    cve_details: str,
    cwe: str,
    candidates: List[Dict[str, Any]],
    ranked_candidates: List[Dict[str, Any]],
) -> str:
    """
    Second pass: enrich the chosen top-k list with better per-item 'why' and roles,
    keeping order and relevance_score fixed.
    """
    # Only include evidence for the already-selected list to minimize prompt size.
    selected_names = [it.get("function_name") for it in ranked_candidates if isinstance(it, dict)]
    candidate_map = {c.get("function_name"): c for c in candidates}
    packed_selected: List[Dict[str, Any]] = []
    for name in selected_names:
        cand = candidate_map.get(name) or {}
        packed_selected.append({
            "function_name": cand.get("function_name"),
            "post_function_name": cand.get("post_function_name"),
            "vulnerable_code_location": _clip_text(cand.get("vulnerable_code_location", ""), limit=180),
            "data_flow_trace": _clip_text(cand.get("data_flow_trace", ""), limit=360),
            "dangerous_operations": _clip_text(cand.get("dangerous_operations", ""), limit=160),
            "input_sources": _clip_text(cand.get("input_sources", ""), limit=160),
        })

    # Provide fixed order + scores to prevent duplicates or reordering.
    fixed = [
        {
            "rank": it.get("rank"),
            "function_name": it.get("function_name"),
            "post_function_name": it.get("post_function_name"),
            "relevance_score": it.get("relevance_score"),
        }
        for it in ranked_candidates
        if isinstance(it, dict)
    ]

    return f"""Enrich the following top-k ranking with stronger, evidence-grounded explanations.

Hard requirements:
- Keep the SAME order, SAME function names, and SAME relevance_score values as provided.
- ranked_candidates MUST have the same length as Provided ranking.
- Each why must be 1-2 sentences and must reference concrete evidence fields (sink + source) when present.
- Do NOT introduce new candidates not in Provided ranking.
- If you choose a unique primary, it MUST be rank 1 and verdict Primary; otherwise primary_* = null.

CVE Description:
{cve_details or "No CVE description provided."}

CWE:
{cwe or "Unknown"}

Provided ranking (fixed order + scores):
{json.dumps(fixed, ensure_ascii=False, separators=(",", ":"))}

Evidence (compact per-candidate fields):
{json.dumps(packed_selected, ensure_ascii=False, separators=(",", ":"))}

Output ONLY valid JSON in this format:
{{
  "primary_cve_root_function": <string or null>,
  "primary_post_function": <string or null>,
  "selection_reason": <string>,
  "global_confidence": <int 0-100>,
  "ranked_candidates": [
    {{
      "rank": <int>,
      "function_name": <string>,
      "post_function_name": <string>,
      "verdict": "Primary" or "Rejected" or "Candidate",
      "attack_chain_role": "entry point" or "intermediate" or "helper" or "downstream manifestation",
      "relevance_score": <int 0-100>,
      "why": <string>,
      "confidence": <int 0-100>
    }}
  ]
}}"""


def _build_compact_full_ranking_prompt(
    cve_details: str,
    cwe: str,
    candidates: List[Dict[str, Any]],
    primary_hint: Optional[str],
) -> str:
    """
    Compact fallback prompt to force a complete permutation ranking when the
    normal tournament JSON is truncated / invalid / top-k only.

    Output is intentionally small: names + scores, plus optional primary.
    """
    compact_candidates: List[Dict[str, Any]] = []
    for cand in candidates:
        compact_candidates.append({
            "function_name": cand.get("function_name"),
            "post_function_name": cand.get("post_function_name"),
            "vulnerable_code_location": _clip_text(cand.get("vulnerable_code_location", ""), limit=140),
            "data_flow_trace": _clip_text(cand.get("data_flow_trace", ""), limit=260),
            "dangerous_operations": _clip_text(cand.get("dangerous_operations", ""), limit=120),
            "input_sources": _clip_text(cand.get("input_sources", ""), limit=120),
        })

    candidate_block = json.dumps(compact_candidates, ensure_ascii=False, separators=(",", ":"))
    hint = primary_hint if primary_hint else None

    return f"""Return a COMPLETE relevance ranking for ALL candidates for a single CVE.

Hard requirements:
- ranked_function_names MUST be a permutation of ALL candidate function_name values (no missing, no duplicates, no extra names).
- relevance_scores MUST be same length as ranked_function_names; each score is 0-100.
- Rank by strict relevance to the CURRENT CVE description (not generic dangerousness).
- If you can justify a unique primary root function, set primary_cve_root_function accordingly; otherwise null.
- If a primary is selected, it MUST be ranked first.

CVE Description:
{cve_details or "No CVE description provided."}

CWE:
{cwe or "Unknown"}

Primary hint (may be null):
{json.dumps(hint, ensure_ascii=False)}

Candidates (compact fields):
{candidate_block}

Output ONLY valid JSON:
{{
  "primary_cve_root_function": <string or null>,
  "primary_post_function": <string or null>,
  "selection_reason": <string>,
  "global_confidence": <int 0-100>,
  "ranked_function_names": [<string>, ...],
  "relevance_scores": [<int>, ...]
}}"""


def _parse_compact_full_ranking(
    payload: Any,
    candidates: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    if not isinstance(payload, dict):
        return None
    ranked_names = payload.get("ranked_function_names")
    scores = payload.get("relevance_scores")
    if not isinstance(ranked_names, list) or not isinstance(scores, list):
        return None
    if len(ranked_names) != len(scores):
        return None

    candidate_names = [c.get("function_name") for c in candidates if isinstance(c.get("function_name"), str)]
    candidate_set = set(candidate_names)
    if len(ranked_names) != len(candidate_names):
        return None
    if len(set(ranked_names)) != len(ranked_names):
        return None
    if set(ranked_names) != candidate_set:
        return None

    candidate_map = {c["function_name"]: c for c in candidates}
    primary = payload.get("primary_cve_root_function")
    if primary not in candidate_set:
        primary = None

    # If primary exists, enforce primary first.
    if primary and ranked_names and ranked_names[0] != primary:
        return None

    ranked_candidates: List[Dict[str, Any]] = []
    for idx, (name, score) in enumerate(zip(ranked_names, scores), 1):
        cand = candidate_map[name]
        ranked_candidates.append({
            "rank": idx,
            "function_name": name,
            "post_function_name": cand.get("post_function_name"),
            "verdict": "Primary" if primary and name == primary else "Candidate",
            "attack_chain_role": (cand.get("per_function_attribution") or {}).get("attack_chain_role", "Unknown"),
            "relevance_score": _safe_int(score, 0),
            "why": "",
            "confidence": _safe_int((cand.get("per_function_attribution") or {}).get("confidence"), 0),
        })

    return {
        "primary_cve_root_function": primary,
        "primary_post_function": payload.get("primary_post_function") if primary else None,
        "selection_reason": payload.get("selection_reason", ""),
        "global_confidence": _safe_int(payload.get("global_confidence"), 0),
        "ranked_candidates": ranked_candidates,
    }


def extract_best_json_object(text: str) -> Optional[Dict[str, Any]]:
    """Extract the most complete JSON object embedded in a text blob."""
    if not text:
        return None

    decoder = json.JSONDecoder()
    best_obj: Optional[Dict[str, Any]] = None
    best_start: Optional[int] = None
    best_end = -1

    for idx, ch in enumerate(text):
        if ch != "{":
            continue
        try:
            obj, end = decoder.raw_decode(text[idx:])
        except json.JSONDecodeError:
            continue
        abs_end = idx + end
        if not isinstance(obj, dict):
            continue
        if abs_end > best_end or (abs_end == best_end and (best_start is None or idx < best_start)):
            best_obj = obj
            best_start = idx
            best_end = abs_end

    return best_obj


def build_structured_function_results(
    gathered_results: List[tuple[int, str]],
    func_paths: List[tuple[str, str]]
) -> List[Dict[str, Any]]:
    structured_results: List[Dict[str, Any]] = []

    for index, raw_result in sorted(gathered_results, key=lambda item: item[0]):
        pre_path, post_path = func_paths[index]
        parsed_result = extract_best_json_object(raw_result) if isinstance(raw_result, str) else None
        # If raw_result contains both stage-1 fenced JSON and a ReAct JSON blob, preserve the
        # stage-1 Scenario/Property fields when the chosen parsed_result does not include them.
        if isinstance(raw_result, str) and isinstance(parsed_result, dict):
            try:
                m = re.search(r"translated:\s*```json\s*(\{[\s\S]*?\})\s*```", raw_result)
                if m:
                    stage1_text = m.group(1)
                    stage1_obj = json.loads(stage1_text)
                    if isinstance(stage1_obj, dict):
                        for k in ("scenario_match", "property_match", "Scenario_match & Property_match", "reason"):
                            if k in stage1_obj and k not in parsed_result:
                                parsed_result[k] = stage1_obj[k]
            except Exception:
                pass
        structured_results.append({
            "index": index,
            "pre_path": pre_path,
            "post_path": post_path,
            "pre_function_name": os.path.splitext(os.path.basename(pre_path))[0],
            "post_function_name": os.path.splitext(os.path.basename(post_path))[0],
            "raw_result": raw_result,
            "parsed_result": parsed_result,
        })

    return structured_results


def _dump_structured_results_json(structured_results: List[Dict[str, Any]], out_path: str | Path) -> None:
    try:
        p = Path(out_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(structured_results, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"Failed to write structured_results JSON to {out_path}: {e}")


def _load_structured_results_json(in_path: str | Path) -> List[Dict[str, Any]]:
    p = Path(in_path)
    if p.is_dir():
        p = p / "structured_results.json"
    with open(p, "r", encoding="utf-8") as f:
        payload = json.load(f)
    if not isinstance(payload, list):
        raise ValueError(f"structured_results JSON must be a list, got: {type(payload).__name__}")
    return [item for item in payload if isinstance(item, dict)]


def _normalize_yes_no(value: Any) -> str:
    return str(value or "").strip().lower()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _clip_text(value: Any, limit: int = 400) -> str:
    text = str(value or "").strip()
    if limit is None or limit < 0:  # None or negative limit means no truncation
        return text
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def build_tournament_candidates(
    structured_results: List[Dict[str, Any]],
    *,
    require_is_cve_root_function: bool = True,
) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []

    for entry in structured_results:
        parsed = entry.get("parsed_result")
        if not isinstance(parsed, dict):
            continue

        if _normalize_yes_no(parsed.get("scenario_match")) != "yes":
            continue

        if _normalize_yes_no(parsed.get("vulnerability_found")) != "yes":
            continue

        attribution = parsed.get("CVE_Attribution") or {}
        if require_is_cve_root_function and _normalize_yes_no(attribution.get("is_cve_root_function")) != "yes":
            continue

        vuln_details = parsed.get("vulnerability_details") or {}
        evidence = parsed.get("evidence") or {}
        fix_analysis = parsed.get("fix_analysis") or {}

        candidates.append({
            "function_name": entry["pre_function_name"],
            "post_function_name": entry["post_function_name"],
            "vulnerability_found": parsed.get("vulnerability_found", "Unknown"),
            "severity": parsed.get("severity", "Unknown"),
            "vulnerable_code_location": _clip_text(parsed.get("vulnerable_code_location", "Not analyzed")),
            "root_cause": _clip_text(vuln_details.get("root_cause", "Not analyzed")),
            "attack_vector": _clip_text(vuln_details.get("attack_vector", "Not analyzed")),
            "impact": _clip_text(vuln_details.get("impact", "Not analyzed")),
            "is_fixed": fix_analysis.get("is_fixed", "Unknown"),
            "fix_description": _clip_text(fix_analysis.get("fix_description", "Not analyzed")),
            "data_flow_trace": _clip_text(evidence.get("data_flow_trace", "Not analyzed"), limit=600),
            "dangerous_operations": _clip_text(evidence.get("dangerous_operations", "Not analyzed")),
            "input_sources": _clip_text(evidence.get("input_sources", "Not analyzed")),
            "reason": [_clip_text(item, limit=220) for item in (parsed.get("reason") or [])[:4]],
            "intermediate_steps_count": parsed.get("intermediate_steps_count", 0),
            "per_function_attribution": {
                "is_cve_root_function": attribution.get("is_cve_root_function", "Unknown"),
                "attack_chain_role": attribution.get("attack_chain_role", "Unknown"),
                "can_other_functions_explain_cve": attribution.get("can_other_functions_explain_cve", "Unknown"),
                "confidence": attribution.get("confidence", 0),
                "reasoning": _clip_text(attribution.get("reasoning", ""), limit=500),
            },
        })

    return candidates


def build_default_tournament_result(candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not candidates:
        return {
            "status": "skipped",
            "candidate_count": 0,
            "primary_cve_root_function": None,
            "primary_post_function": None,
            "selection_reason": "No per-function candidates were marked as CVE root function.",
            "global_confidence": 0,
            "ranked_candidates": [],
        }

    if len(candidates) == 1:
        only = candidates[0]
        return {
            "status": "single_candidate",
            "candidate_count": 1,
            "primary_cve_root_function": only["function_name"],
            "primary_post_function": only["post_function_name"],
            "selection_reason": "Only one candidate survived per-function attribution, so it is selected as the unique primary CVE root function.",
            "global_confidence": _safe_int(only["per_function_attribution"].get("confidence"), 80),
            "ranked_candidates": [
                {
                    "rank": 1,
                    "function_name": only["function_name"],
                    "post_function_name": only["post_function_name"],
                    "verdict": "Primary",
                    "attack_chain_role": only["per_function_attribution"].get("attack_chain_role", "Unknown"),
                    "relevance_score": _safe_int(only["per_function_attribution"].get("confidence"), 80),
                    "why": "Only remaining candidate after per-function attribution.",
                    "confidence": _safe_int(only["per_function_attribution"].get("confidence"), 80),
                }
            ],
        }

    return {
        "status": "tournament_unavailable",
        "candidate_count": len(candidates),
        "primary_cve_root_function": None,
        "primary_post_function": None,
        "selection_reason": "Global tournament output was unavailable or invalid, so no valid full ranking could be produced.",
        "global_confidence": 0,
        "candidates_considered": [candidate["function_name"] for candidate in candidates],
        "ranked_candidates": [],
    }


def _normalize_ranked_candidates(
    ranked_candidates: Any,
    candidates: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    candidate_map = {candidate["function_name"]: candidate for candidate in candidates}
    normalized: List[Dict[str, Any]] = []

    if isinstance(ranked_candidates, list):
        for item in ranked_candidates:
            if not isinstance(item, dict):
                continue
            function_name = item.get("function_name")
            if function_name not in candidate_map:
                continue
            candidate = candidate_map[function_name]
            relevance_score = _safe_int(item.get("relevance_score"), 0)
            normalized.append({
                "function_name": function_name,
                "post_function_name": item.get("post_function_name") or candidate["post_function_name"],
                "verdict": item.get("verdict", "Candidate"),
                "attack_chain_role": item.get("attack_chain_role") or candidate["per_function_attribution"].get("attack_chain_role", "Unknown"),
                "relevance_score": relevance_score,
                "why": _clip_text(item.get("why", ""), limit=400),
                "confidence": _safe_int(item.get("confidence"), 0),
                "rank": _safe_int(item.get("rank"), 0),
            })

    if not normalized:
        return []

    # Prefer model-provided rank order when present; otherwise fall back to score sorting.
    if any(_safe_int(item.get("rank"), 0) > 0 for item in normalized):
        normalized.sort(key=lambda item: _safe_int(item.get("rank"), 0))
    else:
        normalized.sort(
            key=lambda item: (
                _safe_int(item.get("relevance_score"), 0),
                _safe_int(item.get("confidence"), 0),
            ),
            reverse=True
        )
    for idx, item in enumerate(normalized, 1):
        item["rank"] = idx
    return normalized


def _is_valid_tournament_result_shape(result: Any) -> bool:
    return (
        isinstance(result, dict)
        and "selection_reason" in result
        and "ranked_candidates" in result
        and isinstance(result.get("ranked_candidates"), list)
    )


def _ranking_is_complete(ranked_candidates: List[Dict[str, Any]], candidates: List[Dict[str, Any]]) -> bool:
    candidate_names = [candidate["function_name"] for candidate in candidates]
    ranked_names = [item.get("function_name") for item in ranked_candidates if isinstance(item, dict)]
    return (
        len(ranked_names) == len(candidate_names)
        and len(set(ranked_names)) == len(candidate_names)
        and set(ranked_names) == set(candidate_names)
    )

def _topk_is_valid(
    ranked_candidates: List[Dict[str, Any]],
    candidates: List[Dict[str, Any]],
    top_k: int,
) -> bool:
    if top_k <= 0:
        return False
    candidate_names = {candidate["function_name"] for candidate in candidates}
    ranked_names = [item.get("function_name") for item in ranked_candidates if isinstance(item, dict)]
    if not ranked_names:
        return False
    if any(name not in candidate_names for name in ranked_names):
        return False
    if len(set(ranked_names)) != len(ranked_names):
        return False
    expected = min(top_k, len(candidates))
    return len(ranked_names) == expected

def _compact_candidates_for_tournament_prompt(
    candidates: List[Dict[str, Any]],
    *,
    limit_loc: int = 140,
    limit_flow: int = 260,
    limit_ops: int = 120,
    limit_src: int = 120,
) -> List[Dict[str, Any]]:
    """
    Reduce token usage for large tournaments by keeping only the most
    discriminative evidence fields, clipped to short lengths.
    """
    packed: List[Dict[str, Any]] = []
    for cand in candidates:
        packed.append({
            "function_name": cand.get("function_name"),
            "post_function_name": cand.get("post_function_name"),
            "vulnerable_code_location": _clip_text(cand.get("vulnerable_code_location", ""), limit=limit_loc),
            "data_flow_trace": _clip_text(cand.get("data_flow_trace", ""), limit=limit_flow),
            "dangerous_operations": _clip_text(cand.get("dangerous_operations", ""), limit=limit_ops),
            "input_sources": _clip_text(cand.get("input_sources", ""), limit=limit_src),
        })
    return packed


def _candidate_relevance_text(candidate: Dict[str, Any]) -> str:
    parts: List[str] = []
    for key in (
        "vulnerable_code_location",
        "root_cause",
        "attack_vector",
        "impact",
        "fix_description",
        "data_flow_trace",
        "dangerous_operations",
        "input_sources",
    ):
        value = candidate.get(key)
        if isinstance(value, str) and value:
            parts.append(value)
    reason = candidate.get("reason")
    if isinstance(reason, list):
        parts.extend(str(item) for item in reason if isinstance(item, str))
    return " ".join(parts)


def _tokenize(text: str) -> List[str]:
    if not isinstance(text, str) or not text:
        return []
    return re.findall(r"[a-zA-Z0-9_]+", text.lower())


def _build_heuristic_why(cve_details: str, cwe: str, candidate: Dict[str, Any]) -> str:
    """
    Build a detailed 'why' explanation for heuristic-scored candidates.
    Binds the candidate evidence to CVE description specifics and CWE context.
    """
    parts: List[str] = []

    # Extract key evidence from candidate
    ops = str(candidate.get("dangerous_operations", "") or "").lower()
    flow = str(candidate.get("data_flow_trace", "") or "").lower()
    loc = str(candidate.get("vulnerable_code_location", "") or "").lower()
    inputs = str(candidate.get("input_sources", "") or "").lower()

    # CWE-specific sink mapping and evidence extraction
    cwe_norm = (cwe or "").strip().upper()

    if cwe_norm in {"CWE-77", "CWE-78"}:
        # Command injection - look for command execution APIs
        if any(k in ops for k in ("system", "popen", "exec", "dosystem", "cstesystem")):
            sink = next((k for k in ("cstesystem", "system", "popen", "exec", "dosystem") if k in ops), "")
            if sink:
                parts.append(f"Direct {sink} call")
        if "sprintf" in ops or "snprintf" in ops:
            parts.append("Command built with sprintf/snprintf")
    elif cwe_norm in {"CWE-787", "CWE-121", "CWE-120", "CWE-119"}:
        # Buffer overflow - look for buffer operations
        if any(k in ops for k in ("strcpy", "strcat", "memcpy", "sprintf", "snprintf")):
            sink = next((k for k in ("strcpy", "strcat", "memcpy", "sprintf", "snprintf") if k in ops), "")
            if sink:
                parts.append(f"Uses {sink} without bounds")
    elif cwe_norm in {"CWE-22", "CWE-23"}:
        # Path traversal - look for file operations
        if any(k in ops for k in ("open", "fopen", "unlink", "remove", "readfile")):
            sink = next((k for k in ("open", "fopen", "unlink", "remove", "readfile") if k in ops), "")
            if sink:
                parts.append(f"{sink} with untrusted path")

    # Data flow directness
    if "->" in flow:
        step_count = flow.count("->")
        if step_count <= 2:
            parts.append("Direct data flow")
        else:
            parts.append(f"Indirect flow ({step_count}+ transforms)")

    # Input source and attacker control
    if "untrusted" in inputs or "attacker" in inputs or "user" in inputs or "external" in inputs:
        parts.append("Attacker-controlled input")
    elif "parameter" in inputs or "argument" in inputs:
        parts.append("Parameter-driven input path")

    # Match with CVE keywords
    if cve_details:
        cve_lower = cve_details.lower()
        if "injection" in cve_lower and ("inject" in ops or "inject" in flow):
            parts.append("Injection vector confirmed")
        if "overflow" in cve_lower and any(k in ops for k in ("strcpy", "memcpy", "strcat")):
            parts.append("Overflow risk confirmed")

    if not parts:
        parts.append("Heuristic match with CVE context")

    # Combine into concise statement (aim for ~40-60 words)
    why = "; ".join(parts[:3])
    if len(why) > 240:
        why = why[:237] + "..."

    return why


def _heuristic_relevance_score(cve_details: str, cwe: str, candidate: Dict[str, Any]) -> int:
    """
    Deterministic, non-LLM fallback score for ranking candidates by CVE relevance.

    This is intentionally conservative: it prioritizes explicit overlap between
    the CVE description and per-function evidence (data_flow_trace / sinks / ops),
    and down-weights entries with "Unknown"/"Not analyzed" evidence.
    """
    cve_text = cve_details or ""
    cand_text = _candidate_relevance_text(candidate)

    cve_tokens = set(_tokenize(cve_text))
    cand_tokens = set(_tokenize(cand_text))

    overlap = len(cve_tokens & cand_tokens)
    base = 0
    if cve_tokens:
        base = int(55 * (overlap / max(1, len(cve_tokens))))
    else:
        # No CVE text: fall back to "evidence-rich" candidates.
        base = 15

    cwe_norm = (cwe or "").strip().upper()
    ops = str(candidate.get("dangerous_operations", "") or "").lower()
    flow = str(candidate.get("data_flow_trace", "") or "").lower()
    loc = str(candidate.get("vulnerable_code_location", "") or "").lower()
    evidence_blob = " ".join([ops, flow, loc])

    # CWE-specific sink heuristics (small, stable list; no token burn).
    sink_bonus = 0
    if cwe_norm in {"CWE-77", "CWE-78"}:
        if any(k in evidence_blob for k in ("system", "popen", "exec", "dosystem", "cstesystem", "get_cmd_result", "cstesystem(")):
            sink_bonus += 30
        if any(k in evidence_blob for k in ("snprintf", "sprintf")) and any(k in evidence_blob for k in ("echo -n", "md5sum", "awk", "rm -f", "tar -z")):
            sink_bonus += 10
    elif cwe_norm in {"CWE-787", "CWE-121", "CWE-120", "CWE-119"}:
        if any(k in evidence_blob for k in ("strcpy", "strcat", "sprintf", "snprintf", "memcpy", "sscanf", "gets")):
            sink_bonus += 30
    elif cwe_norm in {"CWE-22", "CWE-23"}:
        if any(k in evidence_blob for k in ("open", "fopen", "unlink", "remove", "readfile", "f_read", "f_write")):
            sink_bonus += 25

    # Evidence quality penalties: "Unknown"/"Not analyzed" should not be treated as positive evidence.
    penalty = 0
    for bad in ("unknown", "not analyzed", "not_analyzed"):
        if bad in ops.lower():
            penalty += 8
        if bad in flow.lower():
            penalty += 8
        if bad in str(candidate.get("input_sources", "") or "").lower():
            penalty += 6

    # Reward concrete propagation chains ("->") and visible sink keywords.
    richness = 0
    if "->" in flow:
        richness += min(15, flow.count("->") * 2)
    if any(k in ops for k in ("system", "strcpy", "sprintf", "snprintf", "memcpy", "sscanf", "dosystem", "cstesystem")):
        richness += 8

    score = base + sink_bonus + richness - penalty
    return max(0, min(100, int(score)))


def _complete_ranked_candidates(
    partial_ranked: List[Dict[str, Any]],
    cve_details: str,
    cwe: str,
    candidates: List[Dict[str, Any]],
    primary_winner: Optional[str],
) -> List[Dict[str, Any]]:
    candidate_map = {candidate["function_name"]: candidate for candidate in candidates}
    working: Dict[str, Dict[str, Any]] = {}

    # Keep what the model produced (if any), but ensure shape is consistent.
    for item in partial_ranked or []:
        if not isinstance(item, dict):
            continue
        name = item.get("function_name")
        if name not in candidate_map:
            continue
        cloned = dict(item)
        cloned["post_function_name"] = cloned.get("post_function_name") or candidate_map[name]["post_function_name"]
        cloned["attack_chain_role"] = cloned.get("attack_chain_role") or candidate_map[name]["per_function_attribution"].get("attack_chain_role", "Unknown")
        cloned["relevance_score"] = _safe_int(cloned.get("relevance_score"), 0)
        cloned["confidence"] = _safe_int(cloned.get("confidence"), 0)
        cloned["why"] = _clip_text(cloned.get("why", ""), limit=240)
        cloned["verdict"] = cloned.get("verdict") or "Candidate"
        working[name] = cloned

    # Fill any candidates the model omitted using heuristic scoring.
    for name, cand in candidate_map.items():
        if name in working:
            continue
        h_score = _heuristic_relevance_score(cve_details, cwe, cand)
        h_why = _build_heuristic_why(cve_details, cwe, cand)
        working[name] = {
            "function_name": name,
            "post_function_name": cand["post_function_name"],
            "verdict": "Candidate",
            "attack_chain_role": cand["per_function_attribution"].get("attack_chain_role", "Unknown"),
            "relevance_score": h_score,
            "why": h_why,
            "confidence": _safe_int(cand["per_function_attribution"].get("confidence"), 0),
            "rank": 0,
            "scored_by": "heuristic",
        }

    ranked = list(working.values())

    # Ensure Primary winner is rank 1 if valid; otherwise demote all Primaries to Candidate.
    primary_name = primary_winner if primary_winner in candidate_map else None
    if primary_name:
        for item in ranked:
            if str(item.get("verdict", "")).strip().lower() == "primary" and item.get("function_name") != primary_name:
                item["verdict"] = "Rejected" if str(item.get("verdict", "")).strip().lower() == "rejected" else "Candidate"
        winner_item = ranked.pop(next(i for i, it in enumerate(ranked) if it.get("function_name") == primary_name))
        winner_item["verdict"] = "Primary"
        ranked.sort(key=lambda it: (_safe_int(it.get("relevance_score"), 0), _safe_int(it.get("confidence"), 0)), reverse=True)
        ranked.insert(0, winner_item)
    else:
        for item in ranked:
            if str(item.get("verdict", "")).strip().lower() == "primary":
                item["verdict"] = "Candidate"
        ranked.sort(key=lambda it: (_safe_int(it.get("relevance_score"), 0), _safe_int(it.get("confidence"), 0)), reverse=True)

    for idx, item in enumerate(ranked, 1):
        item["rank"] = idx

    return ranked


def _build_ranking_repair_prompt(
    cve_details: str,
    cwe: str,
    candidates: List[Dict[str, Any]],
    previous_raw_result: str,
) -> str:
    candidate_block = json.dumps(candidates, ensure_ascii=False, indent=2)
    return f"""You previously failed to return a complete global ranking for all tournament candidates.

You MUST rank EVERY candidate exactly once according to strict relevance to the CURRENT CVE description.

Requirements:
- Include every function from Candidates exactly once in ranked_candidates.
- Do NOT return only top-k.
- Rank by strict CVE-specific relevance, not generic dangerousness.
- If a valid primary_cve_root_function is selected, ranked_candidates[0] MUST be that same function and MUST have verdict Primary.
- If no unique primary winner is supported, set primary_cve_root_function and primary_post_function to null, but still rank ALL candidates.
- Do NOT mention any function outside the provided Candidates list.

CVE Description:
{cve_details or "No CVE description provided."}

CWE:
{cwe or "Unknown"}

Candidates:
{candidate_block}

Previous incomplete response:
{_clip_text(previous_raw_result, limit=3000)}

Return ONLY valid JSON in the same schema as before."""

def _build_topk_ranking_repair_prompt(
    cve_details: str,
    cwe: str,
    candidates: List[Dict[str, Any]],
    previous_raw_result: str,
    top_k: int,
) -> str:
    packed = _compact_candidates_for_tournament_prompt(candidates)
    candidate_block = json.dumps(packed, ensure_ascii=False, separators=(",", ":"))
    return f"""You previously failed to return a valid top-{top_k} ranking for tournament candidates.

You MUST consider ALL candidates, but output ONLY the top-{top_k} most CVE-relevant ones.

Hard requirements:
- ranked_candidates MUST contain EXACTLY {min(top_k, len(candidates))} unique items.
- Each item MUST include: rank, function_name, post_function_name, verdict, attack_chain_role, relevance_score, why, confidence.
- Do NOT include candidates outside the provided list.
- If you select a unique primary_cve_root_function, it MUST be ranked first and have verdict Primary.
- Keep each why <= 20 words.

CVE Description:
{cve_details or "No CVE description provided."}

CWE:
{cwe or "Unknown"}

Candidates (compact fields):
{candidate_block}

Previous invalid response excerpt:
{_clip_text(previous_raw_result, limit=1500)}

Output ONLY valid JSON in this exact format:
{{
  "primary_cve_root_function": <string or null>,
  "primary_post_function": <string or null>,
  "selection_reason": <string>,
  "global_confidence": <int 0-100>,
  "ranked_candidates": [
    {{
      "rank": <int starting at 1>,
      "function_name": <string>,
      "post_function_name": <string>,
      "verdict": "Primary" or "Rejected" or "Candidate",
      "attack_chain_role": "entry point" or "intermediate" or "helper" or "downstream manifestation",
      "relevance_score": <int 0-100>,
      "why": <string>,
      "confidence": <int 0-100>
    }}
  ]
}}"""


def _promote_primary_to_rank1(
    ranked_candidates: List[Dict[str, Any]],
    winner: str,
    candidates: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    if not winner:
        return ranked_candidates

    working = [dict(item) for item in ranked_candidates if isinstance(item, dict)]
    winner_index = next((idx for idx, item in enumerate(working) if item.get("function_name") == winner), None)

    if winner_index is None:
        return working

    winner_item = working.pop(winner_index)
    winner_item["verdict"] = "Primary"
    working.insert(0, winner_item)

    for idx, item in enumerate(working, 1):
        item["rank"] = idx
        if idx > 1 and str(item.get("verdict", "")).strip().lower() == "primary":
            item["verdict"] = "Candidate"
    return working


def _demote_primary_verdicts(ranked_candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    cleaned: List[Dict[str, Any]] = []
    for idx, item in enumerate(ranked_candidates, 1):
        if not isinstance(item, dict):
            continue
        cloned = dict(item)
        if str(cloned.get("verdict", "")).strip().lower() == "primary":
            cloned["verdict"] = "Candidate"
        cloned["rank"] = idx
        cleaned.append(cloned)
    return cleaned


async def run_global_attribution_tournament(
    structured_results: List[Dict[str, Any]],
    cve_details: str,
    cwe: str,
    model_name: str = DEFAULT_LLM_CONFIG_KEY,
    *,
    require_is_cve_root_function: bool = True,
) -> Dict[str, Any]:
    candidates = build_tournament_candidates(
        structured_results,
        require_is_cve_root_function=require_is_cve_root_function,
    )
    default_result = build_default_tournament_result(candidates)

    if len(candidates) <= 1:
        return default_result

    TOP_K = 20
    use_topk_mode = len(candidates) > TOP_K

    if use_topk_mode:
        # Two-stage top-k: compact selection for stability, then details for better 'why'.
        compact_topk_prompt = _build_compact_topk_prompt(cve_details, cwe, candidates, TOP_K)
        compact_topk_raw = await async_gpt_inference(
            prompt=compact_topk_prompt,
            temperature=0,
            max_tokens=2048,
            default_system_prompt="You are a strict cross-function security adjudicator.",
            tag="global_attribution_tournament_compact_topk",
            model_name=model_name,
        )
        compact_topk_parsed = extract_best_json_object(compact_topk_raw)
        compact_topk = _parse_compact_topk(compact_topk_parsed, candidates, TOP_K)
        if compact_topk:
            details_prompt = _build_topk_details_prompt(cve_details, cwe, candidates, compact_topk["ranked_candidates"])
            details_raw = await async_gpt_inference(
                prompt=details_prompt,
                temperature=0,
                max_tokens=4096,
                default_system_prompt="You are a strict cross-function security adjudicator.",
                tag="global_attribution_tournament_topk_details",
                model_name=model_name,
            )
            details_parsed = extract_best_json_object(details_raw)
            if _is_valid_tournament_result_shape(details_parsed):
                parsed_result = details_parsed
                ranked_candidates = _normalize_ranked_candidates(parsed_result.get("ranked_candidates"), candidates)
                # Validate and return even if model returns fewer than TOP_K; do not drop to empty.
                winner = parsed_result.get("primary_cve_root_function")
                winner = winner if winner in {c["function_name"] for c in candidates} else None
                if winner:
                    ranked_candidates = _promote_primary_to_rank1(ranked_candidates, winner, candidates)
                else:
                    ranked_candidates = _demote_primary_verdicts(ranked_candidates)
                parsed_result["primary_cve_root_function"] = winner
                parsed_result["primary_post_function"] = next(
                    (c["post_function_name"] for c in candidates if c["function_name"] == winner),
                    None,
                ) if winner else None
                parsed_result["status"] = "top_candidates"
                parsed_result["candidate_count"] = len(candidates)
                parsed_result["candidates_considered"] = [candidate["function_name"] for candidate in candidates]
                parsed_result["ranked_candidates"] = ranked_candidates
                parsed_result["top_10_candidates"] = ranked_candidates[:10]
                parsed_result["top_k_candidates"] = ranked_candidates
                parsed_result["raw_response_excerpt"] = (
                    _clip_text(compact_topk_raw, limit=None)
                    + "\n\n--- topk details ---\n\n"
                    + _clip_text(details_raw, limit=None)
                )
                return parsed_result

            # Details failed: return compact top-k rather than empty.
            compact_topk["status"] = "top_candidates_compact"
            compact_topk["candidate_count"] = len(candidates)
            compact_topk["candidates_considered"] = [candidate["function_name"] for candidate in candidates]
            compact_topk["top_10_candidates"] = compact_topk["ranked_candidates"][:10]
            compact_topk["top_k_candidates"] = compact_topk["ranked_candidates"]
            compact_topk["raw_response_excerpt"] = _clip_text(compact_topk_raw, limit=None) + "\n\n--- topk details (invalid) ---\n\n" + _clip_text(details_raw, limit=None)
            return compact_topk

        packed_candidates = _compact_candidates_for_tournament_prompt(candidates)
        candidate_block = json.dumps(packed_candidates, ensure_ascii=False, separators=(",", ":"))
        prompt = GLOBAL_ATTRIBUTION_TOURNAMENT_TOPK_PROMPT.format(
            top_k=TOP_K,
            cve_description=cve_details or "No CVE description provided.",
            cwe_id=cwe or "Unknown",
            candidate_block=candidate_block,
        )
        max_tokens = 4096
    else:
        candidate_block = json.dumps(candidates, ensure_ascii=False, indent=2)
        prompt = GLOBAL_ATTRIBUTION_TOURNAMENT_PROMPT.format(
            cve_description=cve_details or "No CVE description provided.",
            cwe_id=cwe or "Unknown",
            candidate_block=candidate_block,
        )
        max_tokens = 8192

    raw_result = await async_gpt_inference(
        prompt=prompt,
        temperature=0,
        max_tokens=max_tokens,
        default_system_prompt="You are a strict cross-function security adjudicator.",
        tag="global_attribution_tournament",
        model_name=model_name
    )

    parsed_result = extract_best_json_object(raw_result)
    if not _is_valid_tournament_result_shape(parsed_result):
        parsed_result = {
            "primary_cve_root_function": None,
            "primary_post_function": None,
            "selection_reason": "Global tournament output was unavailable or invalid.",
            "global_confidence": 0,
            "ranked_candidates": [],
        }

    ranked_candidates = _normalize_ranked_candidates(parsed_result.get("ranked_candidates"), candidates)
    if use_topk_mode:
        if not _topk_is_valid(ranked_candidates, candidates, TOP_K):
            repair_prompt = _build_topk_ranking_repair_prompt(cve_details, cwe, candidates, raw_result, TOP_K)
            repair_raw_result = await async_gpt_inference(
                prompt=repair_prompt,
                temperature=0,
                max_tokens=4096,
                default_system_prompt="You are a strict cross-function security adjudicator.",
                tag="global_attribution_tournament_repair",
                model_name=model_name
            )
            repair_parsed_result = extract_best_json_object(repair_raw_result)
            if _is_valid_tournament_result_shape(repair_parsed_result):
                parsed_result = repair_parsed_result
                raw_result = repair_raw_result
                ranked_candidates = _normalize_ranked_candidates(parsed_result.get("ranked_candidates"), candidates)

        # If still invalid, surface a clean fallback without fabricating scores.
        if not _topk_is_valid(ranked_candidates, candidates, TOP_K):
            parsed_result["status"] = "top_candidates_incomplete"
            parsed_result["candidate_count"] = len(candidates)
            parsed_result["candidates_considered"] = [candidate["function_name"] for candidate in candidates]
            parsed_result["ranked_candidates"] = ranked_candidates
            parsed_result["issues"] = {
                "expected_top_k": min(TOP_K, len(candidates)),
                "returned_count": len(ranked_candidates),
                "returned_unique_count": len({it.get("function_name") for it in ranked_candidates if isinstance(it, dict)}),
            }
            parsed_result["raw_response_excerpt"] = _clip_text(raw_result, limit=None)
            return parsed_result
    elif not _ranking_is_complete(ranked_candidates, candidates):
        repair_prompt = _build_ranking_repair_prompt(cve_details, cwe, candidates, raw_result)
        repair_raw_result = await async_gpt_inference(
            prompt=repair_prompt,
            temperature=0,
            max_tokens=8192,
            default_system_prompt="You are a strict cross-function security adjudicator.",
            tag="global_attribution_tournament_repair",
            model_name=model_name
        )
        repair_parsed_result = extract_best_json_object(repair_raw_result)
        if _is_valid_tournament_result_shape(repair_parsed_result):
            parsed_result = repair_parsed_result
            raw_result = repair_raw_result
            ranked_candidates = _normalize_ranked_candidates(parsed_result.get("ranked_candidates"), candidates)

    candidate_names = {candidate["function_name"] for candidate in candidates}
    winner = parsed_result.get("primary_cve_root_function")
    if winner not in candidate_names:
        winner = None

    if use_topk_mode:
        # In top-k mode, LLM returns the top-k most relevant candidates.
        # Append any remaining candidates (not in top-k) using heuristic scoring so
        # ranked_candidates always covers every entry in candidates_considered.
        if winner:
            ranked_candidates = _promote_primary_to_rank1(ranked_candidates, winner, candidates)
        else:
            ranked_candidates = _demote_primary_verdicts(ranked_candidates)

        llm_ranked_names = {item["function_name"] for item in ranked_candidates if isinstance(item, dict)}
        tail: List[Dict[str, Any]] = []
        for cand in candidates:
            name = cand["function_name"]
            if name in llm_ranked_names:
                continue
            h_score = _heuristic_relevance_score(cve_details, cwe, cand)
            h_why = _build_heuristic_why(cve_details, cwe, cand)
            tail.append({
                "function_name": name,
                "post_function_name": cand["post_function_name"],
                "verdict": "Candidate",
                "attack_chain_role": cand["per_function_attribution"].get("attack_chain_role", "Unknown"),
                "relevance_score": h_score,
                "why": h_why,
                "confidence": _safe_int(cand["per_function_attribution"].get("confidence"), 0),
                "rank": 0,
                "scored_by": "heuristic",
            })
        tail.sort(key=lambda it: it["relevance_score"], reverse=True)
        full_ranked = ranked_candidates + tail
        for idx, item in enumerate(full_ranked, 1):
            item["rank"] = idx

        parsed_result["primary_cve_root_function"] = winner
        parsed_result["primary_post_function"] = next(
            (c["post_function_name"] for c in candidates if c["function_name"] == winner),
            None,
        ) if winner else None
        parsed_result["global_confidence"] = _safe_int(parsed_result.get("global_confidence"), 0)
        parsed_result["status"] = "top_candidates"
        parsed_result["candidate_count"] = len(candidates)
        parsed_result["candidates_considered"] = [candidate["function_name"] for candidate in candidates]
        parsed_result["ranked_candidates"] = full_ranked
        parsed_result["top_10_candidates"] = full_ranked[:10]
        parsed_result["top_k_candidates"] = ranked_candidates  # LLM-ranked portion only
        parsed_result["raw_response_excerpt"] = _clip_text(raw_result, limit=None)
        return parsed_result

    full_ranked = _complete_ranked_candidates(ranked_candidates, cve_details, cwe, candidates, winner)
    if not _ranking_is_complete(full_ranked, candidates):
        # Compact retry: ask the model for a permutation list + scores only.
        compact_prompt = _build_compact_full_ranking_prompt(cve_details, cwe, candidates, winner)
        compact_raw = await async_gpt_inference(
            prompt=compact_prompt,
            temperature=0,
            max_tokens=4096,
            default_system_prompt="You are a strict cross-function security adjudicator.",
            tag="global_attribution_tournament_compact_full_ranking",
            model_name=model_name,
        )
        compact_parsed = extract_best_json_object(compact_raw)
        compact_ranked = _parse_compact_full_ranking(compact_parsed, candidates)
        if compact_ranked:
            parsed_result.update(compact_ranked)
            full_ranked = compact_ranked["ranked_candidates"]
            winner = compact_ranked.get("primary_cve_root_function")
            if winner:
                parsed_result["primary_post_function"] = next(
                    (c["post_function_name"] for c in candidates if c["function_name"] == winner),
                    parsed_result.get("primary_post_function"),
                )
            parsed_result["status"] = "completed"
            parsed_result["candidate_count"] = len(candidates)
            parsed_result["candidates_considered"] = [candidate["function_name"] for candidate in candidates]
            parsed_result["raw_response_excerpt"] = _clip_text(raw_result, limit=None) + "\n\n--- compact retry ---\n\n" + _clip_text(compact_raw, limit=None)
            return parsed_result

        ranked_names = [item.get("function_name") for item in full_ranked if isinstance(item, dict)]
        missing = sorted(candidate_names - set(ranked_names))
        parsed_result["status"] = "incomplete_ranking"
        parsed_result["selection_reason"] = (
            parsed_result.get("selection_reason")
            or "Global tournament did not return a valid full ranking that covers all candidates exactly once."
        )
        parsed_result["global_confidence"] = _safe_int(parsed_result.get("global_confidence"), 0)
        parsed_result["candidate_count"] = len(candidates)
        parsed_result["candidates_considered"] = [candidate["function_name"] for candidate in candidates]
        parsed_result["missing_candidates"] = missing
        parsed_result["ranked_candidates"] = full_ranked
        parsed_result["raw_response_excerpt"] = _clip_text(raw_result, limit=None) + "\n\n--- compact retry ---\n\n" + _clip_text(compact_raw, limit=None)
        return parsed_result

    # If the model didn't produce a valid unique Primary winner, keep primary_* null but still rank all.
    if not winner:
        parsed_result["primary_cve_root_function"] = None
        parsed_result["primary_post_function"] = None
        parsed_result["selection_reason"] = parsed_result.get("selection_reason") or (
            "Global tournament did not identify a unique Primary winner; returning a full relevance ranking over all candidates."
        )
        parsed_result["global_confidence"] = _safe_int(parsed_result.get("global_confidence"), 0)
        parsed_result["status"] = "completed"
    else:
        parsed_result["primary_cve_root_function"] = winner
        parsed_result["primary_post_function"] = next(
            (c["post_function_name"] for c in candidates if c["function_name"] == winner),
            parsed_result.get("primary_post_function"),
        )
        parsed_result["global_confidence"] = _safe_int(parsed_result.get("global_confidence"), 0)
        parsed_result["status"] = "completed"

    parsed_result["ranked_candidates"] = full_ranked
    parsed_result["candidate_count"] = len(candidates)
    parsed_result["candidates_considered"] = [candidate["function_name"] for candidate in candidates]
    parsed_result["raw_response_excerpt"] = _clip_text(raw_result, limit=None)
    return parsed_result


def load_vulnerability_scenarios():
    """translatedScenariotranslatedProperty"""
    if not os.path.exists(VULNERABILITY_SCENARIOS_FILE):
        return {}
    
    try:
        with open(VULNERABILITY_SCENARIOS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"translated: {e}")
        return {}

def save_vulnerability_scenarios(scenarios):
    """translatedScenariotranslatedProperty"""
    try:
        with open(VULNERABILITY_SCENARIOS_FILE, 'w', encoding='utf-8') as f:
            json.dump(scenarios, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        logger.error(f"translated: {e}")
        return False

def generate_vulnerability_scenario(vulnerability_type):
    """translatedScenariotranslatedProperty"""
    prompt = GENERATE_SCENARIO_PROMPT.replace("{$vulnerability_type$}", vulnerability_type)
    
    try:
        result = gpt_inference(
            prompt=prompt,
            temperature=0,
            default_system_prompt="You are a security expert who can generate accurate vulnerability scenarios and properties."
        )
        
        scenario_data = json.loads(result)
        return scenario_data
    except Exception as e:
        logger.error(f"translated: {e}")
        return None

def get_vulnerability_scenario(vulnerability_type):
    """translatedScenariotranslatedProperty,translated"""
    scenarios = load_vulnerability_scenarios()
    
    if vulnerability_type in scenarios:
        return scenarios[vulnerability_type]
    
    scenario_data = generate_vulnerability_scenario(vulnerability_type)
    if scenario_data:
        scenarios[vulnerability_type] = scenario_data
        save_vulnerability_scenarios(scenarios)
        return scenario_data
    
    return None

def load_cwe_samples(samples_path=None):
    """translatedCWEtranslated"""
    if samples_path is None:
        samples_path = os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "data", "cwe_samples.json")
        )
        if not os.path.exists(samples_path):
            logger.warning(f"translatedcwe_samples.jsontranslated,translated: {samples_path}")
            return {}
    
    try:
        with open(samples_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"translatedcwe_samples.jsontranslated: {e}")
        return {}

def select_cwe_samples(cwe_type, samples, num_positive=3, num_negative=3):
    """translatedCWEtranslated"""
    cwe_samples = samples.get(cwe_type, [])
    if not cwe_samples:
        logger.warning(f"translated{cwe_type}translated")
        return [], []
    
    positive_samples = [s for s in cwe_samples if s.get('is_positive', False)]
    negative_samples = [s for s in cwe_samples if not s.get('is_positive', False)]
    
    selected_positive = random.sample(positive_samples, min(num_positive, len(positive_samples)))
    selected_negative = random.sample(negative_samples, min(num_negative, len(negative_samples)))
    
    return selected_positive, selected_negative

def format_samples_for_prompt(positive_samples, negative_samples):
    """translatedPROMPTtranslated"""
    prompt_parts = []
    
    if positive_samples:
        prompt_parts.append("### Examples of True Fixes (Positive)")
        for i, sample in enumerate(positive_samples, 1):
            prompt_parts.append(f"{i}. [True Fix]")
            prompt_parts.append(json.dumps({
                "id": sample.get("id", ""),
                "cwe": sample.get("cwe", ""),
                "before": sample.get("before", ""),
                "after": sample.get("after", ""),
                "rationale": sample.get("rationale", ""),
                "is_positive": True
            }, ensure_ascii=False))
    
    if negative_samples:
        prompt_parts.append("\n\n### Examples of False Fixes (Negative)")
        for i, sample in enumerate(negative_samples, 1):
            prompt_parts.append(f"{i}. [False Fix]")
            prompt_parts.append(f"Before: {sample.get('before', '')}")
            prompt_parts.append(f"After:  {sample.get('after', '')}")
            prompt_parts.append(f"Rationale: {sample.get('rationale', '')}")
            prompt_parts.append(f"(is_positive = false)")
    
    return "\n".join(prompt_parts)

def extract_vulnerability_entries(results: str) -> List[Dict[str, Any]]:
    """translated,translated"""
    from utils.utils import extract_first_json, severity_to_score
    
    entries = []
    sections = re.split(r'===\s+(.+?\.c)\s+vs\s+(.+?\.c)(?:\s+\(ReAct[^)]*\))?\s+===', results)
    
    for idx in range(1, len(sections), 3):
        if idx + 1 >= len(sections):
            break
            
        pre_file = sections[idx]
        post_file = sections[idx + 1]
        content = sections[idx + 2] if idx + 2 < len(sections) else ""
        
        score = 0
        score_match = re.search(r'["\']?translated["\']?\s*[::]\s*(\d+)', content, re.IGNORECASE)
        if score_match:
            score = int(score_match.group(1))
        
        is_vuln = False
        
        result_data = extract_first_json(content)
        if result_data:
            vuln_found = result_data.get("vulnerability_found", "").lower()
            if vuln_found == "yes":
                is_vuln = True
                severity = result_data.get("severity", "")
                json_score = severity_to_score(severity)
                score = max(score, json_score if json_score > 0 else 5)  # translated
        
        if not is_vuln:
            if 'RAGtranslated' in content or 'translated' in content:
                if not re.search(r'(translated|translated|translated|false\s*fix)', content, re.IGNORECASE):
                    is_vuln = True
        
        entries.append({
            'pre_file': pre_file,
            'post_file': post_file,
            'content': content.strip(),
            'score': score,
            'is_vuln': is_vuln,
            'length': len(content)
        })
    
    return entries

def prioritize_entries(entries: List[Dict[str, Any]], max_tokens: int = 60000) -> tuple[List[Dict], List[Dict]]:
    """translated,translated"""
    sorted_entries = sorted(entries, key=lambda x: (x['score'], x['is_vuln']), reverse=True)
    
    high_priority = []
    low_priority = []
    current_tokens = 0
    
    base_tokens = count_tokens(SUMMARY_PROMPT)
    available_tokens = max_tokens - base_tokens - 2000  # translated2000 tokentranslated
    
    for entry in sorted_entries:
        entry_tokens = count_tokens(entry['content'])
        
        if entry['score'] >= 7 or entry['is_vuln']:
            if current_tokens + entry_tokens <= available_tokens:
                high_priority.append(entry)
                current_tokens += entry_tokens
            else:
                low_priority.append(entry)
        else:
            low_priority.append(entry)
    
    for entry in sorted_entries:
        if entry not in high_priority and entry not in low_priority:
            entry_tokens = count_tokens(entry['content'])
            if current_tokens + entry_tokens <= available_tokens:
                high_priority.append(entry)
                current_tokens += entry_tokens
            else:
                low_priority.append(entry)
    
    return high_priority, low_priority


def _parse_ablation_strategy(value: Any) -> int:
    """
    Normalize ablation strategy id in {1,2,3,4}.

    Priority:
    - explicit parameter
    - env var VULN_ABLATION_STRATEGY
    - fallback DEFAULT_ABLATION_STRATEGY
    """
    if value is None or value == "":
        strategy = DEFAULT_ABLATION_STRATEGY
    else:
        try:
            strategy = int(value)
        except (TypeError, ValueError):
            strategy = DEFAULT_ABLATION_STRATEGY
    if strategy not in (1, 2, 3, 4):
        strategy = DEFAULT_ABLATION_STRATEGY
    return strategy


def _read_text_file(path: str, *, max_chars: Optional[int] = None) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = f.read()
    except Exception:
        return ""
    if max_chars is not None and max_chars > 0 and len(data) > max_chars:
        return data[:max_chars]
    return data


def _unified_diff_snippet(before_text: str, after_text: str, *, context_lines: int = 3, max_lines: int = 60) -> str:
    before_lines = (before_text or "").splitlines()
    after_lines = (after_text or "").splitlines()
    diff_lines = list(
        difflib.unified_diff(
            before_lines,
            after_lines,
            fromfile="before",
            tofile="after",
            n=max(0, int(context_lines)),
            lineterm="",
        )
    )
    if max_lines is not None and max_lines > 0 and len(diff_lines) > max_lines:
        diff_lines = diff_lines[:max_lines] + ["... (diff truncated) ..."]
    return "\n".join(diff_lines).strip()


def _diff_stats(diff_text: str) -> Dict[str, Any]:
    add = 0
    remove = 0
    for line in (diff_text or "").splitlines():
        if not line:
            continue
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue
        if line.startswith("+"):
            add += 1
        elif line.startswith("-"):
            remove += 1
    return {"added_lines": add, "removed_lines": remove}


def _build_direct_candidate(
    *,
    pre_path: str,
    post_path: str,
    parsed_result: Optional[Dict[str, Any]] = None,
    diff_max_lines: int = 80,
) -> Dict[str, Any]:
    pre_name = os.path.splitext(os.path.basename(pre_path))[0]
    post_name = os.path.splitext(os.path.basename(post_path))[0]

    before_text = _read_text_file(pre_path, max_chars=200_000)
    after_text = _read_text_file(post_path, max_chars=200_000)
    diff_text = _unified_diff_snippet(before_text, after_text, max_lines=diff_max_lines)

    parsed = parsed_result or {}
    vuln_details = parsed.get("vulnerability_details") or {}
    evidence = parsed.get("evidence") or {}
    attribution = parsed.get("CVE_Attribution") or {}

    return {
        "function_name": pre_name,
        "post_function_name": post_name,
        "pre_path": pre_path,
        "post_path": post_path,
        "scenario_match": parsed.get("scenario_match", "Unknown"),
        "property_match": parsed.get("property_match", "Unknown"),
        "vulnerability_found": parsed.get("vulnerability_found", "Unknown"),
        "severity": parsed.get("severity", "Unknown"),
        "vulnerable_code_location": _clip_text(parsed.get("vulnerable_code_location", ""), limit=220),
        "root_cause": _clip_text(vuln_details.get("root_cause", ""), limit=260),
        "attack_vector": _clip_text(vuln_details.get("attack_vector", ""), limit=220),
        "impact": _clip_text(vuln_details.get("impact", ""), limit=220),
        "data_flow_trace": _clip_text(evidence.get("data_flow_trace", ""), limit=500),
        "dangerous_operations": _clip_text(evidence.get("dangerous_operations", ""), limit=220),
        "input_sources": _clip_text(evidence.get("input_sources", ""), limit=220),
        "per_function_attribution": {
            "is_cve_root_function": attribution.get("is_cve_root_function", "Unknown"),
            "attack_chain_role": attribution.get("attack_chain_role", "Unknown"),
            "confidence": attribution.get("confidence", 0),
            "binding_reason": _clip_text(attribution.get("binding_reason", ""), limit=260),
            "dataflow_evidence": _clip_text(attribution.get("dataflow_evidence", ""), limit=260),
            "reasoning": _clip_text(attribution.get("reasoning", ""), limit=360),
        },
        "diff": _clip_text(diff_text, limit=6000),
        "diff_stats": _diff_stats(diff_text),
    }


def _compact_candidates_for_direct_ranking_prompt(
    candidates: List[Dict[str, Any]],
    *,
    limit_diff: int = 360,
    limit_loc: int = 140,
    limit_flow: int = 220,
) -> List[Dict[str, Any]]:
    packed: List[Dict[str, Any]] = []
    for cand in candidates:
        per_attr = cand.get("per_function_attribution") or {}
        packed.append(
            {
                "function_name": cand.get("function_name"),
                "post_function_name": cand.get("post_function_name"),
                "scenario_match": cand.get("scenario_match"),
                "property_match": cand.get("property_match"),
                "vulnerability_found": cand.get("vulnerability_found"),
                "is_cve_root_function": per_attr.get("is_cve_root_function", "Unknown"),
                "attack_chain_role": per_attr.get("attack_chain_role", "Unknown"),
                "vulnerable_code_location": _clip_text(cand.get("vulnerable_code_location", ""), limit=limit_loc),
                "data_flow_trace": _clip_text(cand.get("data_flow_trace", ""), limit=limit_flow),
                "diff_stats": cand.get("diff_stats") or {},
                "diff": _clip_text(cand.get("diff", ""), limit=limit_diff),
            }
        )
    return packed


def _build_direct_compact_topk_prompt(
    *,
    cve_details: str,
    cwe: str,
    candidates: List[Dict[str, Any]],
    top_k: int,
    strategy: int,
) -> str:
    expected = min(max(1, int(top_k)), len(candidates))
    packed = _compact_candidates_for_direct_ranking_prompt(candidates)
    candidate_block = json.dumps(packed, ensure_ascii=False, separators=(",", ":"))
    # NOTE: For ablation strategies 1/2/3, keep the direct Top-20 prompt minimal:
    # - no extra ranking rules
    # - only one instruction sentence
    # - output only primary + rank + scores (no reasons/roles/confidence)
    return f"""translated CVE Description,translated Candidates translated CVE translated {expected} translated,translated JSON:{{"primary_cve_root_function": <string or null>, "ranked_candidates": [{{"function_name": <string>, "relevance_score": <int>, "rank": <int starting from 1>}}, ...]}}.

CVE Description:
{cve_details or "No CVE description provided."}

CWE:
{cwe or "Unknown"}

Candidates (compact):
{candidate_block}
"""


def _parse_direct_topk_simple(
    payload: Any,
    candidates: List[Dict[str, Any]],
    top_k: int,
) -> Optional[Dict[str, Any]]:
    if not isinstance(payload, dict):
        return None

    expected = min(max(1, int(top_k)), len(candidates))
    candidate_names = {c.get("function_name") for c in candidates if isinstance(c.get("function_name"), str)}

    primary = payload.get("primary_cve_root_function")
    if primary is not None and (not isinstance(primary, str) or primary not in candidate_names):
        primary = None

    ranked_candidates = payload.get("ranked_candidates")
    if isinstance(ranked_candidates, list):
        cleaned: List[Dict[str, Any]] = []
        seen: set[str] = set()
        for item in ranked_candidates:
            if not isinstance(item, dict):
                return None
            name = item.get("function_name")
            if not isinstance(name, str) or name not in candidate_names or name in seen:
                return None
            seen.add(name)
            cleaned.append(
                {
                    "function_name": name,
                    "relevance_score": _safe_int(item.get("relevance_score"), 0),
                    "rank": _safe_int(item.get("rank"), len(cleaned) + 1),
                }
            )
        if len(cleaned) != expected:
            return None
        # Normalize rank to 1..N to avoid gaps/duplicates
        cleaned = [{**it, "rank": idx} for idx, it in enumerate(cleaned, 1)]
        return {"primary_cve_root_function": primary, "ranked_candidates": cleaned}

    # Back-compat: accept (rank, relevance_scores) arrays if the model ignores schema.
    ranked_names = payload.get("rank")
    scores = payload.get("relevance_scores")
    if not isinstance(ranked_names, list) or not isinstance(scores, list):
        return None
    if len(ranked_names) != len(scores) or len(ranked_names) != expected:
        return None
    if any((not isinstance(name, str)) or (name not in candidate_names) for name in ranked_names):
        return None
    if len(set(ranked_names)) != len(ranked_names):
        return None

    cleaned = [
        {"function_name": name, "relevance_score": _safe_int(score, 0), "rank": idx}
        for idx, (name, score) in enumerate(zip(ranked_names, scores), 1)
    ]
    return {"primary_cve_root_function": primary, "ranked_candidates": cleaned}


def _build_direct_topk_details_prompt(
    *,
    cve_details: str,
    cwe: str,
    candidates: List[Dict[str, Any]],
    ranked_candidates: List[Dict[str, Any]],
    strategy: int,
) -> str:
    selected_names = [it.get("function_name") for it in ranked_candidates if isinstance(it, dict)]
    candidate_map = {c.get("function_name"): c for c in candidates}
    packed_selected: List[Dict[str, Any]] = []
    for name in selected_names:
        cand = candidate_map.get(name) or {}
        per_attr = cand.get("per_function_attribution") or {}
        packed_selected.append(
            {
                "function_name": cand.get("function_name"),
                "post_function_name": cand.get("post_function_name"),
                "scenario_match": cand.get("scenario_match"),
                "property_match": cand.get("property_match"),
                "vulnerability_found": cand.get("vulnerability_found"),
                "severity": cand.get("severity"),
                "vulnerable_code_location": _clip_text(cand.get("vulnerable_code_location", ""), limit=260),
                "root_cause": _clip_text(cand.get("root_cause", ""), limit=320),
                "data_flow_trace": _clip_text(cand.get("data_flow_trace", ""), limit=700),
                "dangerous_operations": _clip_text(cand.get("dangerous_operations", ""), limit=260),
                "input_sources": _clip_text(cand.get("input_sources", ""), limit=260),
                "cve_attribution": {
                    "is_cve_root_function": per_attr.get("is_cve_root_function", "Unknown"),
                    "attack_chain_role": per_attr.get("attack_chain_role", "Unknown"),
                    "confidence": per_attr.get("confidence", 0),
                    "binding_reason": _clip_text(per_attr.get("binding_reason", ""), limit=320),
                    "dataflow_evidence": _clip_text(per_attr.get("dataflow_evidence", ""), limit=320),
                },
                "diff_stats": cand.get("diff_stats") or {},
                "diff": _clip_text(cand.get("diff", ""), limit=9000),
            }
        )

    fixed_order = [
        {
            "rank": it.get("rank"),
            "function_name": it.get("function_name"),
            "post_function_name": it.get("post_function_name"),
            "relevance_score": it.get("relevance_score"),
        }
        for it in ranked_candidates
        if isinstance(it, dict)
    ]

    return f"""You are ranking CVE root-cause candidates for a single CVE.

You MUST only rank functions from Selected Candidates.
You may think step-by-step internally, but output ONLY JSON.

Ablation strategy:
{strategy}

CVE Description:
{cve_details or "No CVE description provided."}

CWE:
{cwe or "Unknown"}

Selected Candidates (details):
{json.dumps(packed_selected, ensure_ascii=False, separators=(',', ':'))}

Current order (keep ordering and relevance_score fixed; only fill why/verdict/role/confidence):
{json.dumps(fixed_order, ensure_ascii=False, separators=(',', ':'))}

Output ONLY valid JSON:
{{
  "primary_cve_root_function": <string from Selected Candidates or null>,
  "primary_post_function": <string or null>,
  "selection_reason": <string>,
  "global_confidence": <int 0-100>,
  "ranked_candidates": [
    {{
      "rank": <int starting from 1>,
      "function_name": <string>,
      "post_function_name": <string>,
      "verdict": "Primary" or "Candidate" or "Rejected",
      "attack_chain_role": "entry point" or "intermediate" or "helper" or "downstream manifestation" or "unrelated",
      "relevance_score": <int 0-100>,
      "why": <string <= 25 words>,
      "confidence": <int 0-100>
    }}
  ]
}}"""


async def run_direct_root_cause_topk(
    *,
    candidates: List[Dict[str, Any]],
    cve_details: str,
    cwe: str,
    model_name: str = DEFAULT_LLM_CONFIG_KEY,
    top_k: int = 20,
    strategy: int = 1,
) -> Dict[str, Any]:
    if not candidates:
        return {"primary_cve_root_function": None, "ranked_candidates": []}

    if len(candidates) <= 1:
        only = candidates[0]
        name = only.get("function_name")
        return {
            "primary_cve_root_function": name if isinstance(name, str) else None,
            "ranked_candidates": (
                [{"function_name": name, "relevance_score": 70, "rank": 1}] if isinstance(name, str) else []
            ),
        }

    expected = min(max(1, int(top_k)), len(candidates))

    # Direct Top-k selection (minimal output for ablation strategies 1/2/3)
    direct_prompt = _build_direct_compact_topk_prompt(
        cve_details=cve_details,
        cwe=cwe,
        candidates=candidates,
        top_k=expected,
        strategy=strategy,
    )
    raw = await async_gpt_inference(
        prompt=direct_prompt,
        temperature=0,
        max_tokens=2048,
        default_system_prompt="You are a strict cross-function security adjudicator.",
        tag=f"direct_root_cause_compact_topk_s{strategy}",
        model_name=model_name,
    )
    parsed = extract_best_json_object(raw)
    topk = _parse_direct_topk_simple(parsed, candidates, expected) if parsed is not None else None
    if topk:
        return topk

    # Fallback: return a stable placeholder rather than crashing downstream scripts.
    fallback_names = [c.get("function_name") for c in candidates if isinstance(c.get("function_name"), str)][:expected]
    return {
        "primary_cve_root_function": None,
        "ranked_candidates": [
            {"function_name": name, "relevance_score": 0, "rank": idx} for idx, name in enumerate(fallback_names, 1)
        ],
    }

def create_abbreviated_entry(entry: Dict[str, Any]) -> str:
    """translated"""
    return f"=== {entry['pre_file']} vs {entry['post_file']} ===\n" \
           f"[translated: {entry['score']}] [translated: {entry['length']} translated]\n" \
           f"[translated] translated,translated\n\n"

async def generate_final_summary(results: str, agent: str = "", send_message=None,
                                 tournament_json_path: str = "", cve_number: str = "") -> str:
    """
    Unified summary generation with mode selection.

    Automatically selects between verbose (full analysis) and concise (Top 3) modes
    based on SUMMARY_MODE environment variable.

    Args:
        results: Raw analysis results string
        agent: Agent identifier for messaging
        send_message: Async function for sending messages
        tournament_json_path: Path to global_attribution_tournament.json (for concise mode)
        cve_number: CVE identifier (for concise mode)

    Returns:
        Summary string in selected format
    """
    global SUMMARY_MODE

    logger.info(f"translated {SUMMARY_MODE} translated...")

    if SUMMARY_MODE == "concise":
        if tournament_json_path and os.path.exists(tournament_json_path):
            try:
                summary = format_top3_summary_from_file(
                    tournament_json_path,
                    "",  # translated
                    cve_number
                )
                logger.info("translated")
                return summary
            except Exception as e:
                logger.error(f"translated: {e},translated")
                SUMMARY_MODE = "verbose"
        else:
            logger.warning("tournament JSON translated,translated")
            SUMMARY_MODE = "verbose"

    if SUMMARY_MODE == "verbose":
        return await generate_smart_summary(results, agent, send_message)


def print_summary_mode_info():
    """Print available summary modes and current setting."""
    info = f"""
╔════════════════════════════════════════════════════════╗
║         translated                       ║
╠════════════════════════════════════════════════════════╣
║                                                        ║
║ translated: {SUMMARY_MODE.upper():^42}║
║                                                        ║
║ translated:                                           ║
║   • verbose  translated (translated)                     ║
║     └─ 88translated,5000+ translated                    ║
║     └─ translatedLLMtranslated(translated)                       ║
║     └─ translated               ║
║                                                        ║
║   • concise  translated (translated) ✨ translated               ║
║     └─ translated Top 3 translated,~1000 translated                   ║
║     └─ translated ReAct translated                           ║
║     └─ 0 translatedLLMtranslated(translated)                      ║
║     └─ translated、translated、translated                        ║
║                                                        ║
║ translated:                                            ║
║   export VULN_SUMMARY_MODE=verbose   # translated     ║
║   export VULN_SUMMARY_MODE=concise   # translated     ║
║                                                        ║
╚════════════════════════════════════════════════════════╝
"""
    return info


async def generate_smart_summary(results: str, agent: str, send_message=None) -> str:
    """translated,translatedtokentranslated"""

    entries = extract_vulnerability_entries(results)

    if not entries:
        logger.warning("translated")
        return "translated,translated."
    
    total_tokens = count_tokens(results)
    logger.info(f"translatedtokentranslated: {total_tokens}")
    
    if total_tokens < 60000:  # translated
        summary_prompt = SUMMARY_PROMPT.replace("{$result$}", results)
        return await async_gpt_inference(
            prompt=summary_prompt,
            temperature=0,
            default_system_prompt="You are a security analysis summary assistant.",
            tag="final_summary"
        )
    
    logger.warning(f"translatedtokentranslated({total_tokens})translated,translated")
    
    if send_message:
        await send_message(
            f"⚠️ translated({len(entries)}translated),translated...",
            "message",
            agent=agent
        )
    
    high_priority, low_priority = prioritize_entries(entries)
    
    logger.info(f"translated: {len(high_priority)}, translated: {len(low_priority)}")
    
    summarized_results = []
    
    for entry in high_priority:
        summarized_results.append(f"=== {entry['pre_file']} vs {entry['post_file']} ===\n{entry['content']}\n")
    
    if low_priority:
        summarized_results.append("\n=== translated(translated) ===\n")
        for entry in low_priority:
            summarized_results.append(create_abbreviated_entry(entry))
    
    filtered_results = "\n".join(summarized_results)
    
    filtered_tokens = count_tokens(filtered_results)
    
    if filtered_tokens > 60000:
        logger.warning("translated,translated")
        return await batch_summarize(high_priority, low_priority, agent, send_message)
    
    summary_prompt = SUMMARY_PROMPT.replace("{$result$}", filtered_results)
    final_summary = await async_gpt_inference(
        prompt=summary_prompt,
        temperature=0,
        default_system_prompt="You are a security analysis summary assistant.",
        tag="final_summary"
    )
    
    stats = f"\n\n📊 translated:\n" \
            f"- translated: {len(entries)}\n" \
            f"- translated(>=7translated): {sum(1 for e in entries if e['score'] >= 7)}\n" \
            f"- translated(4-6translated): {sum(1 for e in entries if 4 <= e['score'] < 7)}\n" \
            f"- translated(1-3translated): {sum(1 for e in entries if 1 <= e['score'] < 4)}\n" \
            f"- translated: {len(high_priority)}\n" \
            f"- translated: {len(low_priority)}"
    
    return final_summary + stats

async def batch_summarize(high_priority: List[Dict], low_priority: List[Dict], 
                         agent: str, send_message=None) -> str:
    """translated:translated,translated"""
    
    batch_size = 5  # translated5translated
    batch_summaries = []
    
    for i in range(0, len(high_priority), batch_size):
        batch = high_priority[i:i + batch_size]
        
        if send_message:
            await send_message(
                f"translated {i//batch_size + 1} translated ({len(batch)} translated)...",
                "message",
                agent=agent
            )
        
        batch_content = "\n".join([
            f"=== {e['pre_file']} vs {e['post_file']} ===\n{e['content']}\n"
            for e in batch
        ])
        
        batch_prompt = f"""translated:

{batch_content}

translated:
1. translated
2. translated
3. translated(translated)
"""
        
        try:
            summary = await async_gpt_inference(
                prompt=batch_prompt,
                temperature=0,
                default_system_prompt="You are a security analysis summary assistant."
            )
            batch_summaries.append(f"### translated {i//batch_size + 1} translated:\n{summary}")
        except Exception as e:
            logger.error(f"translated{i//batch_size + 1}translated: {e}")
            batch_summaries.append(f"### translated {i//batch_size + 1}: translated")
    
    final_prompt = f"""translated,translated:

{''.join(batch_summaries)}

translated:
- translated {len(low_priority)} translated

translated:
1. translated
2. translated
3. translated
4. translated(translated)
"""
    
    final_summary = await async_gpt_inference(
        prompt=final_prompt,
        temperature=0,
        default_system_prompt="You are a security analysis summary assistant.",
        tag="final_summary"
    )
    
    all_entries = high_priority + low_priority
    stats = f"\n\n📊 translated:\n" \
            f"- translated: {len(all_entries)}\n" \
            f"- translated(>=7translated): {sum(1 for e in all_entries if e['score'] >= 7)}\n" \
            f"- translated(4-6translated): {sum(1 for e in all_entries if 4 <= e['score'] < 7)}\n" \
            f"- translated(1-3translated): {sum(1 for e in all_entries if 1 <= e['score'] < 4)}\n" \
            f"- translated: {len(batch_summaries)}\n" \
            f"- translated: {len(high_priority)}\n" \
            f"- translated: {len(low_priority)}"
    
    return final_summary + stats


SUMMARY_MODE = os.getenv("VULN_SUMMARY_MODE", "concise").lower()

if SUMMARY_MODE not in ("verbose", "concise"):
    logger.warning(f"Invalid SUMMARY_MODE '{SUMMARY_MODE}', using 'concise' as default")
    SUMMARY_MODE = "concise"

logger.info(f"translated: {SUMMARY_MODE} (translated VULN_SUMMARY_MODE translated)")


def locate_paths(
    chat_id: str,
    history_root: str | Path,
    binary_filename: str,
    *,
    require_results: bool = True,
) -> dict:

    history_root = Path(history_root).expanduser().resolve()
    """
    translated chat_id translated / translated.
    translated dict translated.
    """
    root     = history_root / chat_id
    ida_dir  = root / "ida"
    bd_dir   = root / "bindiff" /binary_filename

    logger.debug("DEBUG  bd_dir =")
    # print("DEBUG  items  =", [p.name for p in bd_dir.iterdir()])
    # matches = sorted(bd_dir.glob("*.results"))
    # print("DEBUG  matches=", [m.name for m in matches])

    work_dir = ida_dir

    matches = sorted(bd_dir.glob("*.results"))
    if not matches:
        raise FileNotFoundError(f"translated {bd_dir} translated *.results")
    results_file = matches[0]

    stamp       = f"{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}_{os.getpid()}"
    out_dir     = bd_dir / f"diff_{stamp}"
    folder_a    = out_dir / "folder_a"
    folder_b    = out_dir / "folder_b"
    log_file    = out_dir / "vuln_analysis_results.json"

    out_dir.mkdir(parents=True, exist_ok=False)

    return dict(
        WORK_DIR=str(work_dir),
        RESULTS_FILE=str(results_file),
        OUTPUT_DIR=str(out_dir),
        FOLDER_A=str(folder_a),
        FOLDER_B=str(folder_b),
        LOG_FILE=str(log_file)
    )


def locate_reuse_only_paths(chat_id: str, history_root: str | Path, binary_filename: str) -> dict:
    history_root = Path(history_root).expanduser().resolve()
    root = history_root / chat_id
    ida_dir = root / "ida"
    bd_dir = root / "bindiff" / binary_filename

    stamp = f"{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}_{os.getpid()}"
    out_dir = bd_dir / f"diff_{stamp}"
    folder_a = out_dir / "folder_a"
    folder_b = out_dir / "folder_b"
    log_file = out_dir / "vuln_analysis_results.json"

    bd_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=False)

    return dict(
        WORK_DIR=str(ida_dir),
        RESULTS_FILE="",
        OUTPUT_DIR=str(out_dir),
        FOLDER_A=str(folder_a),
        FOLDER_B=str(folder_b),
        LOG_FILE=str(log_file),
    )


# =================================================================
def normalize_func_name(name: str) -> str:
    """
    translated BinDiff translated (translated "sub_00415580") translated IDA translated (translated "sub_415580").
    translated sub_ translated,translated.
    - translated '_'(_foo → foo)
    - translated __xxx translated/translated
    """
    if name.startswith("sub_"):
        try:
            address_part = name[4:]
            normalized_address = format(int(address_part, 16), 'X')
            return "sub_" + normalized_address
        except ValueError:
            return name
        
    if name.startswith("_") and not name.startswith("__"):
        return name[1:]
    
    else:
        return name
        
res_pat = re.compile(
    r'^[0-9A-Fa-f]{8,16}\s+[0-9A-Fa-f]{8,16}\s+'
    r'(?P<sim>0\.\d+|1(?:\.0)?)\s+.*?"(?P<fn1>[^"]+)"\s*"(?P<fn2>[^"]+)"'
)

def demangle(mangled: str) -> str:
    """translated c++filt translated."""
    try:
        p = subprocess.run(["c++filt", mangled],
                           capture_output=True, text=True, check=True)
        base = p.stdout.split('(')[0].strip()
        if base:
            return base
    except:
        pass
    m = re.match(r'_Z\d+([A-Za-z_]\w*)', mangled)
    if m:
        base = m.group(1)
        base = re.sub(r'(.*?)(?:PKc|Pc|i|f|d)$', r'\1', base)
        return base
    return mangled

def parse_result_funcs(path):
    mapping = {}
    for L in open(path, 'r', encoding='utf-8'):
        m = res_pat.match(L)
        if not m:
            continue
        if abs(float(m.group("sim")) - 1.0) < 1e-6:
            continue  # translated

        d1 = demangle(m.group("fn1"))  # translated
        d2 = demangle(m.group("fn2"))  # translated
        
        # =================================================================
        # =================================================================
        norm_d1 = normalize_func_name(d1)
        norm_d2 = normalize_func_name(d2)
        # =================================================================

        if norm_d1.startswith("GLOBAL__sub_I") or norm_d2.startswith("GLOBAL__sub_I"):
            continue
        
        mapping[norm_d1] = norm_d2

    return mapping

import re

def split_functions(file_path):
    """
    translated Hex-Rays translated(translated {},translated)

    translated:
    /**********************************************************************
     * translated: saveParentControlInfo (translated: 0x4a081c)
     **********************************************************************/

    translated:
      dict: func_name -> (start_idx, end_idx)
    """
    import re

    hdr_begin = re.compile(r'^\s*/\*{5,}')
    hdr_func  = re.compile(
        r'^\s*\*\s*translated:\s*([A-Za-z_]\w*)\s*\(translated:\s*0x[0-9A-Fa-f]+\)'
    )
    hdr_end   = re.compile(r'^\s*\*{5,}\s*/\s*$')

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.read().splitlines(keepends=True)

    total = len(lines)
    headers = []   # [(func_name, header_start_line)]

    i = 0
    while i < total:
        if not hdr_begin.match(lines[i]):
            i += 1
            continue

        name = None
        j = i + 1

        while j < total and j < i + 12:
            m = hdr_func.match(lines[j])
            if m:
                name = m.group(1)
                break
            j += 1

        if not name:
            i += 1
            continue

        headers.append((name, i))

        while j < total and not hdr_end.match(lines[j]):
            j += 1
        i = j + 1

    funcs = {}
    for idx, (name, start) in enumerate(headers):
        end = headers[idx + 1][1] if idx + 1 < len(headers) else total
        funcs[name] = (start, end)

        if name.startswith("_") and not name.startswith("__"):
            alias = name[1:]
            if alias not in funcs:
                funcs[alias] = (start, end)


    return funcs



def build_pseudo_index(pseudo_file: Optional[str]):
    """translatedCtranslated,translated {file, lines, funcs}."""
    if not pseudo_file or not os.path.exists(pseudo_file):
        logger.warning(f"translatedCtranslated,translated: {pseudo_file}")
        return None

    lines = open(pseudo_file, 'r', encoding='utf-8').read().splitlines(keepends=True)
    funcs = split_functions(pseudo_file)
    return {"file": pseudo_file, "lines": lines, "funcs": funcs}


def extract_call_chain(call_info: Dict[str, Any]) -> List[str]:
    """translated analyze translated,translated,translated callers."""
    if not isinstance(call_info, dict):
        return []

    chain: List[str] = []

    def _clean(items: List[str]) -> List[str]:
        return [x for x in items if x and str(x).lower() not in {"<unknown>", "unknown"}]

    for key in ("call_chain", "callers_chain", "call_chain_text"):
        val = call_info.get(key)
        if isinstance(val, list):
            chain = _clean([str(x).strip() for x in val])
            if chain:
                return chain
        if isinstance(val, str):
            parts = [p.strip() for p in val.split("->")]
            chain = _clean(parts)
            if chain:
                return chain

    func_name = None
    func_obj = call_info.get("function") or {}
    if isinstance(func_obj, dict):
        func_name = func_obj.get("name")
    func_name = func_name or call_info.get("function_name")

    callers = call_info.get("callers", {}) or {}
    if isinstance(callers, dict) and callers:
        ordered = []
        for ea, info in sorted(callers.items(), key=lambda x: str(x[0])):
            name = None
            if isinstance(info, dict):
                name = info.get("name")
            name = name or f"sub_{ea}"
            ordered.append(name)
        ordered = _clean(ordered)
        if func_name:
            ordered.append(func_name)
        chain = ordered
        if chain:
            return chain

    return _clean([func_name]) if func_name else []


def collect_highlight_texts(call_info: Dict[str, Any]) -> List[str]:
    """translated data_flow/translated."""
    if not isinstance(call_info, dict):
        return []

    highlights = set()

    func_obj = call_info.get("function") or {}
    if isinstance(func_obj, dict) and func_obj.get("name"):
        highlights.add(str(func_obj.get("name")))

    chains = call_info.get("chains", []) or []
    for sink in chains:
        snippet = sink.get("snippet")
        callee = sink.get("callee")
        if snippet:
            highlights.add(str(snippet))
        if callee:
            highlights.add(str(callee))

        for arg in sink.get("args", []) or []:
            if arg.get("text"):
                highlights.add(str(arg.get("text")))
            if arg.get("call_text"):
                highlights.add(str(arg.get("call_text")))
            for ch in (arg.get("chains") or []):
                rhs = (ch or {}).get("rhs_class") or {}
                detail = rhs.get("detail") if isinstance(rhs, dict) else None
                if detail:
                    highlights.add(str(detail))

    backward_flow = (call_info.get("data_flow") or {}).get("backward_flow", {}) or {}
    for entries in backward_flow.values():
        for ent in entries or []:
            use_stmt = ent.get("use_stmt_text") or ent.get("use_stmt")
            if use_stmt:
                highlights.add(str(use_stmt))
            for sl in ent.get("slices", []) or []:
                def_stmt = (sl or {}).get("def_stmt") or {}
                def_txt = def_stmt.get("text")
                if def_txt:
                    highlights.add(str(def_txt))

    cleaned = []
    for t in highlights:
        t = t.strip()
        if len(t) > 1:
            cleaned.append(t)
    return cleaned


def slice_function_code(
    index: Dict[str, Any],
    func_name: str,
    danger_api_pat: Optional[re.Pattern] = None,
    highlight_texts: Optional[List[str]] = None,
    slice_before: int = DEFAULT_SLICE_BEFORE,
    slice_after: int = DEFAULT_SLICE_AFTER,
    full_threshold: int = 300,
) -> Optional[Dict[str, Any]]:
    """translated.

    translated:
      1) translated/translated
      2) translated API translated
      3) translated
    """
    if not index or not func_name:
        return None

    funcs = index.get("funcs", {}) or {}
    lines = index.get("lines", []) or []
    if func_name not in funcs:
        return None

    start, end = funcs[func_name]
    func_lines = lines[start:end]
    total = end - start
    if total <= 0:
        return None

    reason = "full_small_func"
    truncated = False
    slice_start, slice_end = 0, total

    if total > full_threshold:
        hl_hits: List[int] = []
        hl_texts = [t.strip().lower() for t in (highlight_texts or []) if t and len(t.strip()) > 1]
        if hl_texts:
            for i, l in enumerate(func_lines):
                low = l.lower()
                if any(t in low for t in hl_texts):
                    hl_hits.append(i)
            if hl_hits:
                h = hl_hits[0]
                slice_start = max(0, h - slice_before)
                slice_end = min(total, h + slice_after + 1)
                reason = "dataflow_hit"
                truncated = True

        if reason == "full_small_func":
            if danger_api_pat:
                hits = [i for i, l in enumerate(func_lines) if danger_api_pat.search(l)]
            else:
                hits = []
            if hits:
                h = hits[0]
                slice_start = max(0, h - slice_before)
                slice_end = min(total, h + slice_after + 1)
                m = danger_api_pat.search(func_lines[h]) if danger_api_pat else None
                reason = f"danger_api_hit:{m.group(0) if m else 'api'}"
                truncated = True

        if reason == "full_small_func":
            slice_start = 0
            slice_end = min(total, slice_before * 2)
            reason = "first_lines"
            truncated = True

    selected = func_lines[slice_start:slice_end]
    if not selected:
        return None

    start_line = slice_start + start + 1
    end_line = slice_start + start + len(selected)

    return {
        "func": func_name,
        "file": index.get("file"),
        "code": "".join(selected),
        "start_line": start_line,
        "end_line": end_line,
        "reason": reason,
        "truncated": truncated,
        "total_lines": total,
    }


def write_extracted(pseudo_file, base_names, out_dir):
    """
    translated base_names translated,translated base_name.c translated.
    """
    os.makedirs(out_dir, exist_ok=True)
    funcs = split_functions(pseudo_file)
    logger.info(f"Hex-Rays functions found: {len(funcs)}")
    lines = open(pseudo_file,'r',encoding='utf-8').read().splitlines(keepends=True)
    for base in base_names:
        if base not in funcs:
            logger.warning(f"translated “{base}”")
            continue
        i,j = funcs[base]
        out = os.path.join(out_dir, f"{base}.c")
        with open(out,'w',encoding='utf-8') as w:
            w.writelines(lines[i:j])
        logger.info(f"extracted {base} → {out}")

class Refiner:
    def __init__(
        self,
        LOG_FILE,
        pre_binary_name=None,
        post_binary_name=None,
        include_call_chain_code: bool = True,
        pseudo_indexes: Optional[Dict[str, Any]] = None,
        slice_before: int = DEFAULT_SLICE_BEFORE,
        slice_after: int = DEFAULT_SLICE_AFTER,
        danger_apis: Optional[List[str]] = None,
        full_func_line_threshold: int = 120,
        use_react_agent: bool = True,
        # When to run ReAct stage after stage-1 Scenario/Property.
        # - "never": never run ReAct (stage-1 only)
        # - "scenario_yes": run ReAct if scenario_match == Yes
        # - "scenario_and_property_yes": run ReAct if (scenario_match == Yes and property_match == Yes)
        react_trigger: str = "scenario_and_property_yes",
        pre_pseudo_file: Optional[str] = None,
        post_pseudo_file: Optional[str] = None,
        react_model_name: str = DEFAULT_LLM_CONFIG_KEY,
        react_max_iterations: int = 20,
        send_message: Optional[Callable] = None,
        history_dir: Optional[str] = None,
    ):
        self.log = LOG_FILE
        self.context_log = f"{LOG_FILE}.ctx"  # translated,translated vuln_analysis_results.json
        self.agent = "Detection Agent"
        self._task_cache = {}  # translated
        self.pre_binary_name = pre_binary_name  # translated
        self.post_binary_name = post_binary_name  # translated

        self.include_call_chain_code = include_call_chain_code
        self.pseudo_indexes = pseudo_indexes or {}
        self.slice_before = slice_before
        self.slice_after = slice_after
        self.full_func_line_threshold = full_func_line_threshold
        self.danger_apis = danger_apis or DEFAULT_DANGER_APIS
        self.danger_api_pattern = (
            re.compile("|".join(re.escape(api) for api in self.danger_apis), re.IGNORECASE)
            if self.danger_apis
            else None
        )
        self.max_call_chain_chars = 100000  # translated,translated
        
        self._binary_locks = {}
        self._lock_access_lock = asyncio.Lock()  # translated _binary_locks translated
        
        self.use_react_agent = use_react_agent
        self.react_trigger = react_trigger
        self.pre_pseudo_file = pre_pseudo_file
        self.post_pseudo_file = post_pseudo_file
        self.react_model_name = react_model_name
        self.react_max_iterations = react_max_iterations
        self.send_message = send_message
        self.history_dir = history_dir

    async def _get_lock_for_binary(self, binary_name):
        async with self._lock_access_lock:
            if binary_name not in self._binary_locks:
                self._binary_locks[binary_name] = asyncio.Lock()
            return self._binary_locks[binary_name]

        #api_key = "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"
        #if not api_key:
        #self.client = OpenAI(api_key=api_key) 

    def make_prompt(self, fa_content, fb_content, cve_details=None, cwe=None, work_mode: str = "reproduction"):
        """translated
        
        Args:
            fa_content: translated
            fb_content: translated
            cve_details: CVEtranslated(translated)translatedCWEtranslated(translated)
            cwe: CWEtranslated
            work_mode: translated - "reproduction"(translated)translated "discovery"(translated)
        """
        scenario = ""
        property = ""
        vulnerability_type = cwe if cwe else "CWE-78"  # translatedCWE-78
        
        if vulnerability_type and (vulnerability_type.startswith('"') and vulnerability_type.endswith('"')):
            vulnerability_type = vulnerability_type[1:-1]
        
        if vulnerability_type:
            scenario_data = get_vulnerability_scenario(vulnerability_type)
            if scenario_data:
                scenario = scenario_data.get("scenario", "")
                property = scenario_data.get("property", "")
        
        if work_mode == "discovery":
            prompt = DISCOVERY_PROMPT.replace("{$vulnerability_type$}", vulnerability_type)
            prompt = prompt.replace("{$cwe_id$}", vulnerability_type)
            prompt = prompt.replace("{$scenario$}", scenario)
            prompt = prompt.replace("{$property$}", property)
            prompt = prompt.replace("{$filea$}", fa_content)
            prompt = prompt.replace("{$fileb$}", fb_content)
            prompt = prompt.replace("{$result$}", "")  # translated,translatedLLMtranslated
        else:
            prompt = BASE_PROMPT.replace("{$vulnerability_type$}", vulnerability_type)
            prompt = prompt.replace("{$scenario$}", scenario)
            prompt = prompt.replace("{$property$}", property)
            prompt = prompt.replace("{$filea$}", fa_content)
            prompt = prompt.replace("{$fileb$}", fb_content)
            prompt = prompt.replace("{$cve_details$}", cve_details if cve_details else "")
        
        return prompt
        
    def make_rag_prompt(self, fa_content, fb_content, pre_func_name, post_func_name, cve_details=None, cwe=None, pre_func_context=None, post_func_context=None, work_mode: str = "reproduction"):
        """translatedRAGtranslated,translated
        
        Args:
            fa_content: translated
            fb_content: translated
            cve_details: CVEtranslated(translated)translatedCWEtranslated(translated)
            cwe: CWEtranslated
            pre_func_context: translated
            post_func_context: translated
            work_mode: translated - "reproduction"(translated)translated "discovery"(translated)
        """
        pre_func_context = pre_func_context or ""
        post_func_context = post_func_context or ""
        cve_details = cve_details or ""
        cwe_samples = load_cwe_samples()
        
        positive_samples, negative_samples = select_cwe_samples(cwe, cwe_samples)
        
        samples_text = format_samples_for_prompt(positive_samples, negative_samples)
        
        context_info = ""
        if pre_func_context:
            context_info += f"\n5. translated:\n{pre_func_context}\n"
        if post_func_context:
            context_info += f"\n6. translated:\n{post_func_context}\n"
        
        rag_prompt = f"""
IMPORTANT:
- There is at most ONE primary CVE root function.
- Most patched functions are NOT the CVE root function.
- Your task is a BINARY DECISION for Function Name (Before): {pre_func_name} only.

- If this function is not strictly necessary to explain the CVE, you MUST answer "No".
Your task is NOT to re-identify generic vulnerabilities.

You are given a function that was already identified as a valid CWE-related vulnerability and confirmed to contain a security-relevant patch：Function Name (Before): {pre_func_name}.

Your ONLY task in this stage is to determine whether THIS function is the PRIMARY vulnerability entry point described in the CVE DESCRIPTION.
If the CVE description does NOT explicitly name a vulnerable function (e.g., authentication bypass, authorization bypass, access control flaw), you must identify the CVE root function based on SEMANTIC ROLE rather than name matching.

You MUST strictly bind your judgment to the CVE DESCRIPTION and the FUNCTION CALL & DATA-FLOW CONTEXT.
If the CVE matches but the data-flow shows the sink argument is not user-controllable, you MUST answer "No" unless the CVE explicitly states otherwise.
You MUST learn from the following real-world repair patterns: {samples_text}

--------------------------------

CVE DESCRIPTION (full reference)
{cve_details}

CWE TYPE
{cwe}

--------------------------------
FUNCTION UNDER ANALYSIS
Function Name (Before): {pre_func_name}
Function Name (After):  {post_func_name}

--------------------------------
PATCHED PSEUDOCODE (IDA)
[Before]
{fa_content}

[After]
{fb_content}

--------------------------------
FUNCTION CALL & DATA-FLOW CONTEXT
[Pre-Patch Context]
{pre_func_context}

[Post-Patch Context]
{post_func_context}

--------------------------------
DECISION CRITERIA (MANDATORY)

STRICT NEGATIVE CONDITIONS (If ANY of these apply, is_cve_root_function MUST be "No"):
1. If input_sources includes "internal" or "constant" or "derived" → Cannot be root cause
2. If another patched function also contains the SAME dangerous_operations → Mark as "intermediate" (not "Yes")
3. If data_flow_trace does NOT show: external_input → this_function → dangerous_operation
4. If the CVE description names a specific parameter/variable and this function does NOT use that parameter
5. If this function is just a wrapper/relay without direct use of attacker data

You must answer the following questions in order:

1. CVE Binding:
   Does this function directly implement the vulnerable behavior described in the CVE,
   such as handling the vulnerable input, command, protocol field, or request?
   Does the Function Name (Before) code use the SAME parameter name(s) in the CVE description as literal keys in input retrieval or equivalent parameter binding in the same request context?
   (Parameter name match = STRONG positive signal)

2. Input Controllability (CRITICAL):
   Is input_sources showing attacker-controllable data? (not internal/constant/derived)
   Can you trace a CLEAR path from the CVE's attack entry point → this function → vulnerable operation?

3. Attack Chain Necessity:
   If this function were NOT vulnerable, would the CVE attack still be possible?
   Or could the CVE be exploited by targeting ANOTHER function instead?

4. Uniqueness (CRITICAL):
   Assuming this function is removed or never existed,
   could ANY OTHER patched function ALONE still fully explain
   the CVE attack scenario and impact described in the CVE?
   Answer "Yes" ONLY if another function could independently serve
   as the CVE root cause WITHOUT relying on this function.



## INPUT FORMAT
[C-like pseudocode Before Code Change]
[filea]

[C-like pseudocode After Code Change]
[fileb]

The CVE_Attribution section is the PRIMARY decision.
Vulnerability_Analysis is provided ONLY as supporting evidence.
If the function is not the CVE root function, keep the analysis concise.

OUTPUT FORMAT (STRICT JSON ONLY)
{{
  "CVE_Attribution": {{
    "is_cve_root_function": "Yes/No",
    "attack_chain_role": "entry point / intermediate / helper / unrelated",
    "can_other_functions_explain_cve": "Yes/No",
    "binding_reason": "Concise explanation strictly grounded in the CVE description",
    "dataflow_evidence": "Concise evidence grounded in the FUNCTION CALL & DATA-FLOW CONTEXT",
    "confidence": "High/Medium/Low"
  }},

  "Vulnerability_Analysis": {{
    "translated": "{cwe}",
    "translated": "translated",
    "translated": "translated",
    "translated": "translated",
    "translated": "translated,translated",
    "translated": "translated,translated",
    "translated": "Yes/No",
    "translated": "1-10"
  }}
}}
translated:

[filea]
{fa_content}
[filea end]

[fileb]
{fb_content}
[fileb end]


[result]

[result end]
"""
        
        return rag_prompt

    async def get_function_call_info(self, binary_name, function_name):
        """translatedIDAtranslated"""
        lock = await self._get_lock_for_binary(binary_name)
        
        async with lock:
            try:
                url = "http://10.12.189.40:5000/get_function_call_info"
                data = {
                    "binary_name": binary_name,
                    "function_name": function_name,
                    "ida_version": "ida64"  # translated64translatedIDA
                }
                
                loop = asyncio.get_event_loop()
                logger.info(f"translated get_function_call_info | url={url} | bin={binary_name} func={function_name}")
                
                def _request():
                    try:
                        return requests.post(url, data=data, timeout=120)
                    except requests.exceptions.ConnectionError:
                        return None

                response = await loop.run_in_executor(None, _request)
                
                if response is None:
                    logger.error(f"translated IDA translated: {url}")
                    return {}

                if response.status_code == 200:
                    payload = response.json()
                    logger.debug(f"get_function_call_info translated: {len(json.dumps(payload, ensure_ascii=False))} translated")
                    return payload
                else:
                    logger.error(f"APItranslated,translated: {response.status_code}")
                    logger.error(f"translated: {response.text}")
                    return {}
            except Exception as e:
                logger.error(f"APItranslated: {e}")
                return {}

    def _collect_call_chain_slices(self, call_info: Dict[str, Any], version_label: str):
        """translated."""
        if not self.include_call_chain_code:
            return [], []

        index = self.pseudo_indexes.get(version_label)
        if not index:
            return [], []

        chain = extract_call_chain(call_info)
        highlight_texts = collect_highlight_texts(call_info)
        slices = []
        for func in chain:
            sl = slice_function_code(
                index,
                func,
                danger_api_pat=self.danger_api_pattern,
                highlight_texts=highlight_texts,
                slice_before=self.slice_before,
                slice_after=self.slice_after,
                full_threshold=self.full_func_line_threshold,
            )
            if sl:
                sl["version"] = version_label
                slices.append(sl)
        return chain, slices

    def _format_call_chain_slices(self, slices: List[Dict[str, Any]], title: str) -> str:
        if not slices:
            return ""
        lines = [title]
        total_chars = 0
        for idx, sl in enumerate(slices, 1):
            header = (
                f"[{idx}] {sl.get('func')} | {os.path.basename(sl.get('file',''))}:{sl.get('start_line')}-{sl.get('end_line')} "
                f"reason={sl.get('reason')}"
            )
            if sl.get("truncated"):
                header += " [slice]"
            lines.append(header)
            code = (sl.get("code") or "").strip("\n")
            if code:
                lines.append(code)
                total_chars += len(code)
            lines.append("")
            if total_chars > self.max_call_chain_chars:
                lines.append("[translated] translated,translated")
                break
        return "\n".join(lines).strip()
    
    # method removed; logic now resides in agent.data_flow_utils
    
        
    async def async_query2bot(self, fa, fb, cve_details=None, cwe=None, work_mode: str = "reproduction") -> str:
        """translatedquery2bottranslated
        
        Args:
            fa: translatedCtranslated
            fb: translatedCtranslated
            cve_details: CVEtranslated(translated)translatedCWEtranslated(translated)
            cwe: CWEtranslated
            work_mode: translated - "reproduction"(translated)translated "discovery"(translated)
        """
        logger.info(f"translated {os.path.basename(fa)} vs {os.path.basename(fb)}, translated: {work_mode}")
        
        cache_key = (os.path.basename(fa), os.path.basename(fb))
        if cache_key in self._task_cache:
            logger.info(f"translated {os.path.basename(fa)} vs {os.path.basename(fb)} translated")
            return self._task_cache[cache_key]

        try:
            a_content = open(fa, 'r', encoding='utf-8').read()
            b_content = open(fb, 'r', encoding='utf-8').read()
        except Exception as e:
            logger.error(f"translated: {e}")
            return f"translated: {str(e)}"

        prompt = self.make_prompt(
            f"File: {os.path.basename(fa)}\n{a_content}",
            f"File: {os.path.basename(fb)}\n{b_content}",
            cve_details=cve_details,
            cwe=cwe,
            work_mode=work_mode
        )

        first_stage_model_name = DEFAULT_LLM_CONFIG_KEY
        logger.info(f"First-stage analysis model: {first_stage_model_name}")

        try:
            result = await async_gpt_inference(
                prompt=prompt,
                temperature=0,
                default_system_prompt="You are a security analysis assistant.",
                tag="first_stage_analysis",
                model_name=first_stage_model_name
            )
        except Exception as e:
            logger.error(f"translated: {e}")
            return f"translated: {str(e)}"

        try:
            with open(self.log, 'a', encoding='utf-8') as w:
                w.write(f"=== {os.path.basename(fa)} vs {os.path.basename(fb)} ===\n")
                w.write(result + "\n\n")
            logger.info(f"translated {self.log}")
        except Exception as e:
            logger.error(f"translated: {e}")
        
        stage1_json = extract_best_json_object(result) if isinstance(result, str) else None
        scenario_yes = False
        property_yes = False
        if isinstance(stage1_json, dict):
            scenario_yes = _normalize_yes_no(stage1_json.get("scenario_match")) == "yes"
            property_yes = _normalize_yes_no(stage1_json.get("property_match")) == "yes"

            combined = stage1_json.get("Scenario_match & Property_match")
            if isinstance(combined, str) and combined.strip().lower() == "yes":
                scenario_yes = True
                property_yes = True

        if isinstance(result, str):
            if not scenario_yes and re.search(r'"?scenario_match"?\s*:\s*"?yes"?', result, re.IGNORECASE):
                scenario_yes = True
            if not property_yes and re.search(r'"?property_match"?\s*:\s*"?yes"?', result, re.IGNORECASE):
                property_yes = True

        trigger = str(getattr(self, "react_trigger", "") or "").strip().lower()
        if trigger in ("never", "no", "false", "0"):
            need_rag = False
        elif trigger in ("scenario_yes", "scenario"):
            need_rag = scenario_yes
        else:
            # Default: scenario_and_property_yes
            need_rag = scenario_yes and property_yes
        
        if need_rag:
            logger.info(f"translated {os.path.basename(fa)} vs {os.path.basename(fb)} translated")
            
            if self.use_react_agent:
                rag_result = await self.async_react_query(
                    fa, fb, cve_details, cwe, work_mode
                )
            else:
                rag_result = await self.async_rag_query2bot(
                    fa, fb, cve_details, cwe,
                    pre_binary_name=self.pre_binary_name,
                    post_binary_name=self.post_binary_name,
                    work_mode=work_mode
                )
            final_result = f"translated:\n{result}\n\nReActtranslated:\n{rag_result}"
        else:
            final_result = result if result else "translated"
        
        self._task_cache[cache_key] = final_result
        return final_result

    async def async_react_query(self, fa, fb, cve_details=None, cwe=None, work_mode: str = "reproduction") -> str:
        """translated ReAct Agent translated

        Args:
            fa: translatedCtranslated
            fb: translatedCtranslated
            cve_details: CVEtranslated
            cwe: CWEtranslated
            work_mode: translated

        Returns:
            translated
        """
        from agent.vuln_react_agent import VulnReActRefiner

        logger.info("translated ReAct Agent...")
        react_refiner = VulnReActRefiner(
            log_file=self.log,
            pre_binary_name=self.pre_binary_name,
            post_binary_name=self.post_binary_name,
            pre_pseudo_file=self.pre_pseudo_file,
            post_pseudo_file=self.post_pseudo_file,
            model_name=self.react_model_name,
            max_iterations=self.react_max_iterations,
            send_message=self.send_message,
            history_dir=self.history_dir
        )

        try:
            result = await react_refiner.refine(
                fa=fa,
                fb=fb,
                cve_details=cve_details or "",
                cwe=cwe or "",
                work_mode=work_mode
            )
            return result
        except Exception as e:
            logger.error(f"ReAct Agent translated: {e}")
            logger.info("translated RAG translated...")
            return await self.async_rag_query2bot(
                fa, fb, cve_details, cwe,
                pre_binary_name=self.pre_binary_name,
                post_binary_name=self.post_binary_name,
                work_mode=work_mode
            )
    
    async def async_rag_query2bot(self, fa, fb, cve_details=None, cwe=None, pre_binary_name=None, post_binary_name=None, work_mode: str = "reproduction") -> str:
        """translatedrag_query2bottranslated,translated(translated,translated)
        
        Args:
            fa: translatedCtranslated
            fb: translatedCtranslated
            cve_details: CVEtranslated
            cwe: CWEtranslated
            pre_binary_name: translated(translated,translated)
            post_binary_name: translated(translated,translated)
            work_mode: translated - "reproduction"(translated)translated "discovery"(translated)
        """
        try:
            a_content = open(fa, 'r', encoding='utf-8').read()
            b_content = open(fb, 'r', encoding='utf-8').read()
        except Exception as e:
            logger.error(f"translated: {e}")
            return "translated"

        pre_func_name = os.path.basename(fa).split('.')[0]
        post_func_name = os.path.basename(fb).split('.')[0]
        
        try:
            if pre_binary_name and post_binary_name:
                logger.info(f"translated: pre={pre_binary_name}, post={post_binary_name}")
            else:
                fa_dir = os.path.dirname(fa)
                fb_dir = os.path.dirname(fb)
    
                binary_filename = os.path.basename(os.path.dirname(os.path.dirname(fa_dir)))
                chat_id = os.path.basename(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(fa_dir)))))
                history_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(fa_dir)))))
    
                pre_binary_name = binary_filename
    
                basename = os.path.basename(binary_filename)
                name_part, ext = os.path.splitext(basename)
    
                post_binary_name = f"{name_part}1{ext}"
    

                logger.info(f"translated: pre={pre_binary_name}, post={post_binary_name}")

            logger.info(f"translated: {pre_func_name} translated {post_func_name} | pre_bin={pre_binary_name}, post_bin={post_binary_name}")
            logger.info(f"translated: {pre_func_name} translated {post_func_name} | pre_bin={pre_binary_name}, post_bin={post_binary_name}")
            pre_func_call_info = await self.get_function_call_info(pre_binary_name, pre_func_name)
            post_func_call_info = await self.get_function_call_info(post_binary_name, post_func_name)
            
            pre_func_context = format_vuln_context(pre_func_call_info)
            post_func_context = format_vuln_context(post_func_call_info)

            try:
                pre_chain, pre_slices = self._collect_call_chain_slices(pre_func_call_info, "pre")
                post_chain, post_slices = self._collect_call_chain_slices(post_func_call_info, "post")

                pre_chain_text = self._format_call_chain_slices(pre_slices, "4️⃣ translated(translated)")
                post_chain_text = self._format_call_chain_slices(post_slices, "4️⃣ translated(translated)")

                if pre_chain_text:
                    pre_func_context = (pre_func_context + "\n\n" + pre_chain_text).strip()
                if post_chain_text:
                    post_func_context = (post_func_context + "\n\n" + post_chain_text).strip()
            except Exception as _err:
                logger.error(f"translated: {_err}")

            if pre_func_context:
                logger.debug("[RAG] translated:\n" + pre_func_context)
            else:
                logger.debug("[RAG] translated: <empty>")
            if post_func_context:
                logger.debug("[RAG] translated:\n" + post_func_context)
            else:
                logger.debug("[RAG] translated: <empty>")

            try:
                with open(self.context_log, 'a', encoding='utf-8') as w:
                    w.write(f"=== Function Context: {os.path.basename(fa)} vs {os.path.basename(fb)} ===\n")
                    w.write("[Pre]\n")
                    w.write((pre_func_context or "<empty>") + "\n")
                    w.write("[Post]\n")
                    w.write((post_func_context or "<empty>") + "\n\n")
            except Exception as _e:
                logger.error(f"translated context_log translated: {_e}")
            
        except Exception as e:
            logger.error(f"translated: {e}")
            pre_func_context = ""  # translated,translated
            post_func_context = ""
        
        logger.info("translated")
        
        prompt = self.make_rag_prompt(
            a_content,
            b_content,
            pre_func_name,
            post_func_name,
            cve_details=cve_details,
            cwe=cwe,
            pre_func_context=pre_func_context,
            post_func_context=post_func_context,
            work_mode=work_mode
        )

        try:
            result = await async_gpt_inference(
                prompt=prompt,
                temperature=0,
                default_system_prompt="You are a security analysis assistant.",
                tag="rag_second_stage"
            )
        except Exception as e:
            logger.error(f"RAGtranslated: {e}")
            return f"RAGtranslated: {str(e)}"

        try:
            with open(self.log, 'a', encoding='utf-8') as w:
                w.write(f"=== {os.path.basename(fa)} vs {os.path.basename(fb)} (RAGtranslated) ===\n")
                w.write(result + "\n\n")
            logger.info(f"translatedRAGtranslated {self.log}")

            with open(self.context_log, 'a', encoding='utf-8') as wctx:
                wctx.write(f"=== {os.path.basename(fa)} vs {os.path.basename(fb)} (RAGtranslated) ===\n")
                wctx.write("[Pre]\n")
                wctx.write((pre_func_context or "<empty>") + "\n")
                wctx.write("[Post]\n")
                wctx.write((post_func_context or "<empty>") + "\n\n")
        except Exception as e:
            logger.error(f"translatedRAGtranslated: {e}")

        return result if result else "RAGtranslated"

async def main(chat_id: str,
         history_root: str | Path,
         binary_filename: str,
         post_binary_filename: str = None,  # translated:translated
         pre_c: str = None, post_c: str = None, cve_details: str = None, cwe: str = None, send_message=None,
         include_call_chain_code: bool = True,
         slice_before: int = DEFAULT_SLICE_BEFORE,
         slice_after: int = DEFAULT_SLICE_AFTER,
         danger_api_list: Optional[List[str]] = None,
         full_func_line_threshold: int = 300,
         work_mode: str = "reproduction",
         ablation_strategy: Optional[int] = None,
         reuse_structured_results_json: Optional[str] = None,
         react_model_name: str = DEFAULT_LLM_CONFIG_KEY,
         react_max_iterations: int = 20):
    """
    translated:translated
    
    Args:
        chat_id: translatedID
        history_root: translated
        binary_filename: translated
        post_binary_filename: translated
        pre_c: translatedCtranslated
        post_c: translatedCtranslated
        cve_details: CVEtranslated(translated)translatedCWEtranslated(translated)
        cwe: CWEtranslated
        send_message: translated
        include_call_chain_code: translated
        slice_before: translated
        slice_after: translated
        danger_api_list: translatedAPItranslated
        full_func_line_threshold: translated
        work_mode: translated - "reproduction"(translated)translated "discovery"(translated)
        react_model_name: ReAct Agent translated(translated config.ini translated LLM.{model_name} translated)
    react_max_iterations: ReAct Agent translated
    """
    wall_start = time.time()
    strategy = _parse_ablation_strategy(ablation_strategy)
    reuse_fast_path = strategy in (3, 4) and bool(reuse_structured_results_json)
    paths = (
        locate_reuse_only_paths(chat_id, history_root, binary_filename)
        if reuse_fast_path
        else locate_paths(chat_id, history_root, binary_filename)
    )
    WORK_DIR     = Path(paths["WORK_DIR"])     
    OUTPUT_DIR   = Path(paths["OUTPUT_DIR"])
    RESULTS_FILE = paths["RESULTS_FILE"]
    FOLDER_A, FOLDER_B = paths["FOLDER_A"], paths["FOLDER_B"]
    LOG_FILE = paths["LOG_FILE"]
    run_log_file = set_log_file(str(OUTPUT_DIR / "pt.log"))


    logger.info("translated:")
    logger.info(f"Per-run log file: {run_log_file}")
    for k, v in paths.items():
        logger.info(f"{k:<12}= {v}")
    logger.info("")

    logger.info(f"[Ablation] strategy={strategy} (VULN_ABLATION_STRATEGY default={DEFAULT_ABLATION_STRATEGY})")

    # Optional fast-path: Strategy 3 can reuse structured_results (typically produced by Strategy 4)
    # to avoid repeating Scenario/Property filtering and ReAct analysis.
    # When enabled, Strategy 3 will run ONLY Direct Top-20 ranking over:
    #   scenario_match==Yes && vulnerability_found==Yes
    if strategy == 3 and reuse_structured_results_json:
        try:
            reused_structured_results = _load_structured_results_json(reuse_structured_results_json)
            logger.info(
                f"[Ablation S3-Reuse] Loaded structured_results: {reuse_structured_results_json} "
                f"(count={len(reused_structured_results)})"
            )
            _dump_structured_results_json(reused_structured_results, OUTPUT_DIR / "structured_results.json")

            filtered: List[Dict[str, Any]] = []
            for entry in reused_structured_results:
                parsed = entry.get("parsed_result")
                if not isinstance(parsed, dict):
                    continue
                if _normalize_yes_no(parsed.get("scenario_match")) != "yes":
                    continue
                if _normalize_yes_no(parsed.get("vulnerability_found")) != "yes":
                    continue
                pre_path = entry.get("pre_path")
                post_path = entry.get("post_path")
                if not isinstance(pre_path, str) or not isinstance(post_path, str):
                    continue
                filtered.append(
                    _build_direct_candidate(
                        pre_path=pre_path,
                        post_path=post_path,
                        parsed_result=parsed,
                    )
                )

            logger.info(f"[Ablation S3-Reuse] Direct ranking candidates after filter: {len(filtered)} / {len(reused_structured_results)}")
            direct_topk_result = await run_direct_root_cause_topk(
                candidates=filtered,
                cve_details=cve_details or "",
                cwe=cwe or "",
                model_name=react_model_name,
                top_k=20,
                strategy=strategy,
            )
            direct_topk_file = OUTPUT_DIR / f"direct_root_cause_top20_strategy{strategy}.json"
            with open(direct_topk_file, "w", encoding="utf-8") as f:
                json.dump(direct_topk_result, f, ensure_ascii=False, indent=2)
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"\n\n=== Direct Root-Cause Top-20 (Strategy {strategy} / Reuse) ===\n")
                f.write(json.dumps(direct_topk_result, ensure_ascii=False, indent=2))
                f.write("\n")

            wall_end = time.time()
            wall_time = wall_end - wall_start
            stats = LLM_STATS.summary()
            logger.info("========== LLM TOKEN & TIME SUMMARY ==========")
            logger.info(json.dumps(stats, indent=2, ensure_ascii=False))
            logger.info("========== WALL TIME ==========")
            logger.info(f"Total wall-clock time: {wall_time:.2f} seconds")
            try:
                with open(LOG_FILE, "a", encoding="utf-8") as f:
                    f.write("\n\n=== LLM TOKEN & TIME SUMMARY ===\n")
                    f.write(json.dumps(stats, indent=2, ensure_ascii=False))
                    f.write("\n\n=== LLM CALL DETAILS ===\n")
                    for r in LLM_STATS.records:
                        f.write(json.dumps(r, ensure_ascii=False) + "\n")
                    f.write("\n=== WALL TIME ===\n")
                    f.write(f"Total wall-clock time: {wall_time:.2f} seconds\n")
            except Exception as e:
                logger.error(f"translated LLM translated: {e}")

            return {
                "strategy": strategy,
                "binary_filename": binary_filename,
                "post_binary_filename": post_binary_filename,
                "OUTPUT_DIR": str(OUTPUT_DIR),
                "LOG_FILE": str(LOG_FILE),
                "RESULTS_FILE": str(RESULTS_FILE),
                "WORK_DIR": str(WORK_DIR),
                "reused_structured_results_json": str(Path(reuse_structured_results_json).resolve()),
            }
        except Exception as e:
            logger.error(f"[Ablation S3-Reuse] Failed: {e}")
            logger.info("[Ablation S3-Reuse] Falling back to full Strategy-3 pipeline.")

    # Optional fast-path: Strategy 4 can reuse the structured_results from Strategy 3 to avoid
    # repeating Scenario/Property filtering and ReAct analysis (saves tokens/time).
    # When enabled, Strategy 4 will run ONLY the global tournament on the reused candidates
    # (Scenario==Yes && vulnerability_found==Yes && is_cve_root_function==Yes).
    if strategy == 4 and reuse_structured_results_json:
        try:
            reused_structured_results = _load_structured_results_json(reuse_structured_results_json)
            logger.info(
                f"[Ablation S4-Reuse] Loaded structured_results: {reuse_structured_results_json} "
                f"(count={len(reused_structured_results)})"
            )

            tournament_result = await run_global_attribution_tournament(
                structured_results=reused_structured_results,
                cve_details=cve_details or "",
                cwe=cwe or "",
                model_name=react_model_name,
                require_is_cve_root_function=True,
            )

            tournament_file = OUTPUT_DIR / "global_attribution_tournament.json"
            with open(tournament_file, "w", encoding="utf-8") as f:
                json.dump(tournament_result, f, ensure_ascii=False, indent=2)

            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write("\n\n=== Global Attribution Tournament (Reuse Strategy-3 Results) ===\n")
                f.write(json.dumps(tournament_result, ensure_ascii=False, indent=2))
                f.write("\n")

            logger.info("[Ablation S4-Reuse] Global Attribution Tournament completed")

            # In reuse mode, skip the optional final-summary LLM call to reduce cost.
            wall_end = time.time()
            wall_time = wall_end - wall_start

            stats = LLM_STATS.summary()
            logger.info("========== LLM TOKEN & TIME SUMMARY ==========")
            logger.info(json.dumps(stats, indent=2, ensure_ascii=False))
            logger.info("========== WALL TIME ==========")
            logger.info(f"Total wall-clock time: {wall_time:.2f} seconds")
            try:
                with open(LOG_FILE, "a", encoding="utf-8") as f:
                    f.write("\n\n=== LLM TOKEN & TIME SUMMARY ===\n")
                    f.write(json.dumps(stats, indent=2, ensure_ascii=False))
                    f.write("\n\n=== LLM CALL DETAILS ===\n")
                    for r in LLM_STATS.records:
                        f.write(json.dumps(r, ensure_ascii=False) + "\n")
                    f.write("\n=== WALL TIME ===\n")
                    f.write(f"Total wall-clock time: {wall_time:.2f} seconds\n")
            except Exception as e:
                logger.error(f"translated LLM translated: {e}")

            return {
                "strategy": strategy,
                "binary_filename": binary_filename,
                "post_binary_filename": post_binary_filename,
                "OUTPUT_DIR": str(OUTPUT_DIR),
                "LOG_FILE": str(LOG_FILE),
                "RESULTS_FILE": str(RESULTS_FILE),
                "WORK_DIR": str(WORK_DIR),
                "reused_structured_results_json": str(Path(reuse_structured_results_json).resolve()),
            }
        except Exception as e:
            logger.error(f"[Ablation S4-Reuse] Failed: {e}")
            logger.info("[Ablation S4-Reuse] Falling back to full Strategy-4 pipeline.")

    # Extract CVE number from binary filename if available
    cve_number = ""
    cve_match = re.search(r'CVE-\d{4}-\d{4,5}', binary_filename)
    if cve_match:
        cve_number = cve_match.group(0)
    logger.info(f"Extracted CVE number: {cve_number or 'Not found'}")

    logger.info(f"translatedCtranslated: {pre_c}")
    logger.info(f"translatedCtranslated: {post_c}")

    pre_index = build_pseudo_index(pre_c) if pre_c else None
    post_index = build_pseudo_index(post_c) if post_c else None
    pseudo_indexes = {}
    if pre_index:
        pseudo_indexes["pre"] = pre_index
    if post_index:
        pseudo_indexes["post"] = post_index

    func_mapping = parse_result_funcs(RESULTS_FILE)
    logger.info(f"translated: {len(func_mapping)}")

    if not func_mapping:
        logger.warning("translated,translated")
        if send_message:
            await send_message(
                "translated",
                "message",
                agent="Detection Agent",
            )
        return

    write_extracted(pre_c, func_mapping.keys(), FOLDER_A)    # translated
    write_extracted(post_c, func_mapping.values(), FOLDER_B) # translated

    func_paths: List[tuple[str, str]] = []
    for pre_func, post_func in func_mapping.items():
        pre_func_path = os.path.join(FOLDER_A, f"{pre_func}.c")
        post_func_path = os.path.join(FOLDER_B, f"{post_func}.c")
        if os.path.exists(pre_func_path) and os.path.exists(post_func_path):
            func_paths.append((pre_func_path, post_func_path))
        else:
            logger.warning(f"translated {pre_func_path} translated {post_func_path},translated")

    direct_topk_result: Optional[Dict[str, Any]] = None
    direct_topk_file: Optional[Path] = None
    tournament_result: Optional[Dict[str, Any]] = None
    tournament_file: Optional[Path] = None

    if strategy == 1:
        direct_candidates = [
            _build_direct_candidate(pre_path=pre_path, post_path=post_path, parsed_result=None)
            for (pre_path, post_path) in func_paths
        ]
        logger.info(f"[Ablation S1] Direct ranking candidates: {len(direct_candidates)}")
        direct_topk_result = await run_direct_root_cause_topk(
            candidates=direct_candidates,
            cve_details=cve_details or "",
            cwe=cwe or "",
            model_name=react_model_name,
            top_k=20,
            strategy=strategy,
        )
        direct_topk_file = OUTPUT_DIR / f"direct_root_cause_top20_strategy{strategy}.json"
        try:
            with open(direct_topk_file, "w", encoding="utf-8") as f:
                json.dump(direct_topk_result, f, ensure_ascii=False, indent=2)
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"\n\n=== Direct Root-Cause Top-20 (Strategy {strategy}) ===\n")
                f.write(json.dumps(direct_topk_result, ensure_ascii=False, indent=2))
                f.write("\n")
        except Exception as e:
            logger.error(f"translated strategy{strategy} Top-20 translated: {e}")

        if send_message:
            top_preview = ", ".join(
                it.get("function_name", "")
                for it in (direct_topk_result.get("ranked_candidates") or [])[:3]
                if isinstance(it, dict)
            ) or "None"
            await send_message(
                f"[Ablation S1] Direct Top-20 done. Top-3 preview: {top_preview}",
                "message",
                agent="Detection Agent",
            )

        structured_results: List[Dict[str, Any]] = []
        gathered_results: List[tuple[int, str]] = []
    else:
        # Strategy 2/3/4: run stage-1 for all, and optionally run ReAct depending on strategy.
        if strategy == 2:
            react_trigger = "never"
            use_react_agent = False
        else:
            # Strategy 3/4: Scenario==Yes enters ReAct
            react_trigger = "scenario_yes"
            use_react_agent = True

        r = Refiner(
            LOG_FILE,
            pre_binary_name=binary_filename,
            post_binary_name=post_binary_filename,
            include_call_chain_code=include_call_chain_code,
            pseudo_indexes=pseudo_indexes,
            slice_before=slice_before,
            slice_after=slice_after,
            danger_apis=danger_api_list,
            full_func_line_threshold=full_func_line_threshold,
            use_react_agent=use_react_agent,
            react_trigger=react_trigger,
            pre_pseudo_file=pre_c,
            post_pseudo_file=post_c,
            react_model_name=react_model_name,  # translated
            react_max_iterations=react_max_iterations,
            send_message=send_message,
            history_dir=str(WORK_DIR),
        )

        tasks: List[Any] = []
        for (pre_func_path, post_func_path) in func_paths:
            tasks.append(r.async_query2bot(pre_func_path, post_func_path, cve_details, cwe, work_mode=work_mode))
    
    if strategy != 1:
        concurrency_limit = 5  # translatedAPItranslated
        semaphore = asyncio.Semaphore(concurrency_limit)

        async def bounded_task_with_send(task, index, pre_path, post_path):
            async with semaphore:
                try:
                    result = await task
                    if send_message:
                        await send_message(
                            f"translated {os.path.basename(pre_path)} vs {os.path.basename(post_path)}translated:\n{result}",
                            "message",
                            agent=r.agent
                        )
                    return index, result
                except Exception as e:
                    logger.error(f"translated: {e}")
                    error_msg = f"translated: {str(e)}"
                    if send_message:
                        await send_message(
                            f"translated {os.path.basename(pre_path)} vs {os.path.basename(post_path)}translated:\n{error_msg}",
                            "message",
                            agent=r.agent
                        )
                    return index, error_msg

        bounded_tasks = [
            bounded_task_with_send(task, i, func_paths[i][0], func_paths[i][1])
            for i, task in enumerate(tasks)
        ]

        gathered_results = await asyncio.gather(*bounded_tasks)
        structured_results = build_structured_function_results(gathered_results, func_paths)
        _dump_structured_results_json(structured_results, OUTPUT_DIR / "structured_results.json")

        if strategy in (2, 3):
            # Strategy 2: Scenario==Yes -> direct Top-20
            # Strategy 3: Scenario==Yes (enter ReAct) -> (scenario_match==Yes & vulnerability_found==Yes) -> direct Top-20
            filtered: List[Dict[str, Any]] = []
            for entry in structured_results:
                parsed = entry.get("parsed_result")
                if not isinstance(parsed, dict):
                    continue
                if _normalize_yes_no(parsed.get("scenario_match")) != "yes":
                    continue
                if strategy == 3:
                    if _normalize_yes_no(parsed.get("vulnerability_found")) != "yes":
                        continue
                filtered.append(
                    _build_direct_candidate(
                        pre_path=entry["pre_path"],
                        post_path=entry["post_path"],
                        parsed_result=parsed,
                    )
                )

            logger.info(f"[Ablation S{strategy}] Direct ranking candidates after filter: {len(filtered)} / {len(structured_results)}")
            direct_topk_result = await run_direct_root_cause_topk(
                candidates=filtered,
                cve_details=cve_details or "",
                cwe=cwe or "",
                model_name=react_model_name,
                top_k=20,
                strategy=strategy,
            )
            direct_topk_file = OUTPUT_DIR / f"direct_root_cause_top20_strategy{strategy}.json"
            try:
                with open(direct_topk_file, "w", encoding="utf-8") as f:
                    json.dump(direct_topk_result, f, ensure_ascii=False, indent=2)
                with open(LOG_FILE, "a", encoding="utf-8") as f:
                    f.write(f"\n\n=== Direct Root-Cause Top-20 (Strategy {strategy}) ===\n")
                    f.write(json.dumps(direct_topk_result, ensure_ascii=False, indent=2))
                    f.write("\n")
            except Exception as e:
                logger.error(f"translated strategy{strategy} Top-20 translated: {e}")

            if send_message:
                top_preview = ", ".join(
                    it.get("function_name", "")
                    for it in (direct_topk_result.get("ranked_candidates") or [])[:3]
                    if isinstance(it, dict)
                ) or "None"
                await send_message(
                    f"[Ablation S{strategy}] Direct Top-20 done. Top-3 preview: {top_preview}",
                    "message",
                    agent=r.agent,
                )
        else:
            # Strategy 4: Full tournament pipeline
            tournament_result = await run_global_attribution_tournament(
                structured_results=structured_results,
                cve_details=cve_details or "",
                cwe=cwe or "",
                model_name=react_model_name
            )

            tournament_file = OUTPUT_DIR / "global_attribution_tournament.json"
            try:
                with open(tournament_file, "w", encoding="utf-8") as f:
                    json.dump(tournament_result, f, ensure_ascii=False, indent=2)

                with open(LOG_FILE, "a", encoding="utf-8") as f:
                    f.write("\n\n=== Global Attribution Tournament ===\n")
                    f.write(json.dumps(tournament_result, ensure_ascii=False, indent=2))
                    f.write("\n")

                logger.info("Global Attribution Tournament completed")
                logger.info(json.dumps(tournament_result, ensure_ascii=False, indent=2))

                if send_message:
                    candidate_count = tournament_result.get("candidate_count", 0)
                    if tournament_result.get("status") == "completed":
                        winner = tournament_result.get("primary_cve_root_function") or "None"
                        message = f"Global Attribution Tournament translated:translated {candidate_count} translated CVE root function = {winner}"
                    elif tournament_result.get("status") == "single_candidate":
                        winner = tournament_result.get("primary_cve_root_function") or "None"
                        message = f"Global Attribution Tournament translated:translated 1 translated,translated CVE root function = {winner}"
                    elif tournament_result.get("status") == "top_candidates":
                        top_candidates = tournament_result.get("top_10_candidates") or []
                        preview = ", ".join(item.get("function_name", "") for item in top_candidates[:3]) or "None"
                        message = f"Global Attribution Tournament translated；translated top-{len(top_candidates)} translated,translated 3 translated {preview}"
                    else:
                        message = "Global Attribution Tournament translated:translated"

                    await send_message(
                        message,
                        "message",
                        agent=r.agent
                    )
            except Exception as e:
                logger.error(f"translated Global Attribution Tournament translated: {e}")

            try:
                with open(LOG_FILE, 'r', encoding='utf-8') as f:
                    results = f.read()

                summary = await generate_final_summary(
                    results,
                    r.agent,
                    send_message,
                    tournament_json_path=str(tournament_file),
                    cve_number=cve_number or ""
                )

                logger.info("translated:")
                logger.info(summary)
                if send_message:
                    await send_message(
                        f"translated:\n{summary}",
                        "message",
                        agent=r.agent
                    )
            except Exception as e:
                logger.error(f"translated: {e}")
                if send_message:
                    await send_message(
                        f"translated",
                        "message",
                        agent=r.agent
                    )

    logger.info("translated！")
    wall_end = time.time()
    wall_time = wall_end - wall_start
    

    stats = LLM_STATS.summary()
    
    logger.info("========== LLM TOKEN & TIME SUMMARY ==========")
    logger.info(json.dumps(stats, indent=2, ensure_ascii=False))

    logger.info("========== WALL TIME ==========")
    logger.info(f"Total wall-clock time: {wall_time:.2f} seconds")
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write("\n\n=== LLM TOKEN & TIME SUMMARY ===\n")
            f.write(json.dumps(stats, indent=2, ensure_ascii=False))
            f.write("\n\n=== LLM CALL DETAILS ===\n")
            for r in LLM_STATS.records:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
            f.write("\n=== WALL TIME ===\n")
            f.write(f"Total wall-clock time: {wall_time:.2f} seconds\n")
    except Exception as e:
        logger.error(f"translated LLM translated: {e}")

    return {
        "strategy": strategy,
        "binary_filename": binary_filename,
        "post_binary_filename": post_binary_filename,
        "OUTPUT_DIR": str(OUTPUT_DIR),
        "LOG_FILE": str(LOG_FILE),
        "RESULTS_FILE": str(RESULTS_FILE),
        "WORK_DIR": str(WORK_DIR),
    }


async def llm_diff(chat_id: str, history_root: str, binary_filename: str, 
                 post_binary_filename: str = None,
                 pre_c: str = None, post_c: str = None, cve_details: str = None, 
                 cwe: str = None, send_message=None,
                 include_call_chain_code: bool = True,
                 slice_before: int = DEFAULT_SLICE_BEFORE,
                 slice_after: int = DEFAULT_SLICE_AFTER,
                 danger_api_list: Optional[List[str]] = None,
                 full_func_line_threshold: int = 300,
                 ablation_strategy: Optional[int] = None,
                 reuse_structured_results_json: Optional[str] = None,
                 react_model_name: str = DEFAULT_LLM_CONFIG_KEY,
                 react_max_iterations: int = 20):
    """translated,translated"""
    return await main(
        chat_id,
        history_root,
        binary_filename,
        post_binary_filename=post_binary_filename,
        pre_c=pre_c,
        post_c=post_c,
        cve_details=cve_details,
        cwe=cwe,
        send_message=send_message,
        include_call_chain_code=include_call_chain_code,
        slice_before=slice_before,
        slice_after=slice_after,
        danger_api_list=danger_api_list,
        full_func_line_threshold=full_func_line_threshold,
        ablation_strategy=ablation_strategy,
        reuse_structured_results_json=reuse_structured_results_json,
        react_model_name=react_model_name,
        react_max_iterations=react_max_iterations,
    )
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2017-17020alphapd",
        post_binary_filename = "CVE-2017-17020alphapd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2017-17020alphapd\CVE-2017-17020alphapd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2017-17020alphapd\CVE-2017-17020alphapd1_pseudo.c",
        cve_details="On D-Link DCS-5009 devices with firmware 1.08.11 and earlier, DCS-5010 devices with firmware 1.14.09 and earlier, and DCS-5020L devices with firmware before 1.15.01, command injection in alphapd (binary responsible for running the camera's web server) allows remote authenticated attackers to execute code through sanitized /setSystemAdmin user input in the AdminID field being passed directly to a call to system.",
        cwe="CWE-78"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2019-10999alphapd",
        post_binary_filename = "CVE-2019-10999alphapd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2019-10999alphapd\CVE-2019-10999alphapd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2019-10999alphapd\CVE-2019-10999alphapd1_pseudo.c",
        cve_details="The D-Link DCS series of Wi-Fi cameras contains a stack-based buffer overflow in alphapd, the camera's web server. The overflow allows a remotely authenticated attacker to execute arbitrary code by providing a long string in the WEPEncryption parameter when requesting wireless.htm. Vulnerable devices include DCS-5009L (1.08.11 and below), DCS-5010L (1.14.09 and below), DCS-5020L (1.15.12 and below), DCS-5025L (1.03.07 and below), DCS-5030L (1.04.10 and below), DCS-930L (2.16.01 and below), DCS-931L (1.14.11 and below), DCS-932L (2.17.01 and below), DCS-933L (1.14.11 and below), and DCS-934L (1.05.04 and below).",
        cwe="CWE-787"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2019-14363upnpd",
        post_binary_filename = "CVE-2019-14363upnpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2019-14363upnpd\CVE-2019-14363upnpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2019-14363upnpd\CVE-2019-14363upnpd1_pseudo.c",
        cve_details="A stack-based buffer overflow in the upnpd binary running on NETGEAR WNDR3400v3 routers with firmware version 1.0.1.18_1.0.63 allows an attacker to remotely execute arbitrary code via a crafted UPnP SSDP packet.",
        cwe="CWE-787"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2019-1663httpd",
        post_binary_filename = "CVE-2019-1663httpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2019-1663httpd\CVE-2019-1663httpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2019-1663httpd\CVE-2019-1663httpd1_pseudo.c",
        cve_details="A vulnerability in the web-based management interface of the Cisco RV110W Wireless-N VPN Firewall, Cisco RV130W Wireless-N Multifunction VPN Router, and Cisco RV215W Wireless-N VPN Router could allow an unauthenticated, remote attacker to execute arbitrary code on an affected device. The vulnerability is due to improper validation of user-supplied data in the web-based management interface. An attacker could exploit this vulnerability by sending malicious HTTP requests to a targeted device. A successful exploit could allow the attacker to execute arbitrary code on the underlying operating system of the affected device as a high-privilege user. RV110W Wireless-N VPN Firewall versions prior to 1.2.2.1 are affected. RV130W Wireless-N Multifunction VPN Router versions prior to 1.0.3.45 are affected. RV215W Wireless-N VPN Router versions prior to 1.3.1.1 are affected.",
        cwe="CWE-787"
    ))
'''
'''

if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2019-20760uhttpd",
        post_binary_filename = "CVE-2019-20760uhttpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2019-20760uhttpd\CVE-2019-20760uhttpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2019-20760uhttpd\CVE-2019-20760uhttpd1_pseudo.c",
        cve_details="NETGEAR R9000 devices before 1.0.4.26 are affected by authentication bypass.",
        cwe="CWE-77"
    ))
'''

'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2019-19824boa",
        post_binary_filename = "CVE-2019-19824boa1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2019-19824boa\CVE-2019-19824boa_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2019-19824boa\CVE-2019-19824boa1_pseudo.c",
        cve_details="On certain TOTOLINK Realtek SDK based routers, an authenticated attacker may execute arbitrary OS commands via the sysCmd parameter to the boafrm/formSysCmd URI, even if the GUI (syscmd.htm) is not available. This allows for full control over the device's internals. This affects A3002RU through 2.0.0, A702R through 2.1.3, N301RT through 2.1.6, N302R through 3.4.0, N300RT through 3.4.0, N200RE through 4.0.0, N150RT through 3.4.0, N100RE through 3.4.0, and N302RE 2.0.2.",
        cwe="CWE-78"
    ))
'''
'''   
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2023-37171shttpd",
        post_binary_filename = "CVE-2023-37171shttpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2023-37171shttpd\CVE-2023-37171shttpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2023-37171shttpd\CVE-2023-37171shttpd1_pseudo.c",
        cve_details="TOTOLINK A3300R V17.0.0cu.557_B20221024 was discovered to contain a command injection vulnerability via the admuser parameter",
        cwe="CWE-78"
    ))
'''

'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2023-37171shttpd",
        post_binary_filename = "CVE-2023-37171shttpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2023-37171shttpd\CVE-2023-37171shttpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2023-37171shttpd\CVE-2023-37171shttpd1_pseudo.c",
        cve_details="TOTOLINK A3300R V17.0.0cu.557_B20221024 was discovered to contain a command injection vulnerability via the ip parameter",
        cwe="CWE-78"
    ))
'''

'''

if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2022-36479cstecgi",
        post_binary_filename = "CVE-2022-36479cstecgi1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2022-36479cstecgi\CVE-2022-36479cstecgi.cgi_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2022-36479cstecgi\CVE-2022-36479cstecgi1.cgi_pseudo.c",
        cve_details="TOTOLINK N350RT V9.3.5u.6139_B20201216 was discovered to contain a command injection vulnerability",
        cwe="CWE-78"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2022-44252cstecgi",
        post_binary_filename = "CVE-2022-44252cstecgi1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2022-44252cstecgi\CVE-2022-44252cstecgi.cgi_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2022-44252cstecgi\CVE-2022-44252cstecgi1.cgi_pseudo.c",
        cve_details="TOTOLINK NR1800X V9.1.0u.6279_B20210910 contains a command injection",
        cwe="CWE-78"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2020-3323httpd",
        post_binary_filename = "CVE-2020-3323httpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2020-3323httpd\CVE-2020-3323httpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2020-3323httpd\CVE-2020-3323httpd1_pseudo.c",
        cve_details="A vulnerability in the web-based management interface of Cisco Small Business RV110W, RV130, RV130W, and RV215W Routers could allow an unauthenticated, remote attacker to execute arbitrary code on an affected device. The vulnerability is due to improper validation of user-supplied input in the web-based management interface. An attacker could exploit this vulnerability by sending crafted HTTP requests to a targeted device. A successful exploit could allow the attacker to execute arbitrary code as the root user on the underlying operating system of the affected device.",
        cwe="CWE-119"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2021-33514libsal.so.0",
        post_binary_filename = "CVE-2021-33514libsal.so.01",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-33514libsal.so.0\CVE-2021-33514libsal.so.0.0_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-33514libsal.so.0\CVE-2021-33514libsal.so.01.0_pseudo.c",
        cve_details="Certain NETGEAR devices are affected by command injection by an unauthenticated attacker via the vulnerable /sqfs/lib/libsal.so.0.0 library used by a CGI application, as demonstrated by setup.cgi?token=';$HTTP_USER_AGENT;' with an OS command in the User-Agent field. ",
        cwe="CWE-78"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2020-3331httpd",
        post_binary_filename = "CVE-2020-3331httpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2020-3331httpd\CVE-2020-3331httpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2020-3331httpd\CVE-2020-3331httpd1_pseudo.c",
        cve_details="A vulnerability in the web-based management interface of Cisco RV110W Wireless-N VPN Firewall and Cisco RV215W Wireless-N VPN Router could allow an unauthenticated, remote attacker to execute arbitrary code on an affected device. The vulnerability is due to improper validation of user-supplied input data by the web-based management interface. An attacker could exploit this vulnerability by sending crafted requests to a targeted device. A successful exploit could allow the attacker to execute arbitrary code with the privileges of the root user.",
        cwe="CWE-119"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2020-24297httpd",
        post_binary_filename = "CVE-2020-24297httpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2020-24297httpd\CVE-2020-24297httpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2020-24297httpd\CVE-2020-24297httpd1_pseudo.c",
        cve_details="httpd on TP-Link TL-WPA4220 devices (versions 2 through 4) allows remote authenticated users to execute arbitrary OS commands by sending crafted POST requests to the endpoint /admin/powerline. Fixed version: TL-WPA4220(EU)_V4_201023",
        cwe="CWE-78"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2020-28005httpd",
        post_binary_filename = "CVE-2020-28005httpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2020-28005httpd\CVE-2020-28005httpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2020-28005httpd\CVE-2020-28005httpd1_pseudo.c",
        cve_details="httpd on TP-Link TL-WPA4220 devices (hardware versions 2 through 4) allows remote authenticated users to trigger a buffer overflow (causing a denial of service) by sending a POST request to the /admin/syslog endpoint. Fixed version: TL-WPA4220(EU)_V4_201023",
        cwe="CWE-120"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2021-20090httpd",
        post_binary_filename = "CVE-2021-20090httpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-20090httpd\CVE-2021-20090httpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-20090httpd\CVE-2021-20090httpd1_pseudo.c",
        cve_details="A path traversal vulnerability in the web interfaces of Buffalo WSR-2533DHPL2 firmware version <= 1.02 and WSR-2533DHP3 firmware version <= 1.24 could allow unauthenticated remote attackers to bypass authentication.",
        cwe="CWE-22"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2021-27239upnpd",
        post_binary_filename = "CVE-2021-27239upnpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-27239upnpd\CVE-2021-27239upnpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-27239upnpd\CVE-2021-27239upnpd1_pseudo.c",
        cve_details="This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of NETGEAR R6400 and R6700 firmware version 1.0.4.98 routers. Authentication is not required to exploit this vulnerability. The specific flaw exists within the upnpd service, which listens on UDP port 1900 by default. A crafted MX header field in an SSDP message can trigger an overflow of a fixed-length stack-based buffer. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-11851.",
        cwe="CWE-121"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2021-27708cstecgi",
        post_binary_filename = "CVE-2021-27708cstecgi1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-27708cstecgi\CVE-2021-27708cstecgi.cgi_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-27708cstecgi\CVE-2021-27708cstecgi1.cgi_pseudo.c",
        cve_details="Command Injection in TOTOLINK X5000R router with firmware v9.1.0u.6118_B20201102, and TOTOLINK A720R router with firmware v4.1.5cu.470_B20200911 allows remote attackers to execute arbitrary OS commands by sending a modified HTTP request. This occurs because the function executes glibc's system function with untrusted input. In the function, 'command' parameter is directly passed to the attacker, allowing them to control the 'command' field to attack the OS.",
        cwe="CWE-78"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2021-34991upnpd",
        post_binary_filename = "CVE-2021-34991upnpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-34991upnpd\CVE-2021-34991upnpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-34991upnpd\CVE-2021-34991upnpd1_pseudo.c",
        cve_details="This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of NETGEAR R6400v2 1.0.4.106_10.0.80 routers. Authentication is not required to exploit this vulnerability. The specific flaw exists within the UPnP service, which listens on TCP port 5000 by default. When parsing the uuid request header, the process does not properly validate the length of user-supplied data prior to copying it to a fixed-length stack-based buffer. An attacker can leverage this vulnerability to execute code in the context of root. Was ZDI-CAN-14110.",
        cwe="CWE-121"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2021-35324cstecgi",
        post_binary_filename = "CVE-2021-35324cstecgi1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-35324cstecgi\CVE-2021-35324cstecgi.cgi_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-35324cstecgi\CVE-2021-35324cstecgi1.cgi_pseudo.c",
        cve_details="A vulnerability in the TOTOLINK A720R A720R_Firmware V4.1.5cu.470_B20200911 allows attackers to bypass authentication.",
        cwe="CWE-287"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2021-44246cstecgi",
        post_binary_filename = "CVE-2021-44246cstecgi1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-44246cstecgi\CVE-2021-44246cstecgi.cgi_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-44246cstecgi\CVE-2021-44246cstecgi1.cgi_pseudo.c",
        cve_details="Totolink devices A3100R v4.1.2cu.5050_B20200504, A830R v5.9c.4729_B20191112, and A720R v4.1.5cu.470_B20200911 were discovered to contain a stack overflow. This vulnerability allows attackers to cause a Denial of Service (DoS) via the IpTo parameter.",
        cwe="CWE-787"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2021-44247cstecgi",
        post_binary_filename = "CVE-2021-44247cstecgi1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-44247cstecgi\CVE-2021-44247cstecgi.cgi_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-44247cstecgi\CVE-2021-44247cstecgi1.cgi_pseudo.c",
        cve_details="Totolink devices A3100R v4.1.2cu.5050_B20200504, A830R v5.9c.4729_B20191112, and A720R v4.1.5cu.470_B20200911 were discovered to contain command injection vulnerability. This vulnerability allows attackers to execute arbitrary commands via the IpFrom parameter.",
        cwe="CWE-77"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2021-45391httpd",
        post_binary_filename = "CVE-2021-45391httpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-45391httpd\CVE-2021-45391httpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-45391httpd\CVE-2021-45391httpd1_pseudo.c",
        cve_details="A Buffer Overflow vulnerability exists in Tenda Router AX12 V22.03.01.21_CN in the goform/setIPv6Status binary file /usr/sbin/httpd via the conType parameter, which causes a Denial of Service.",
        cwe="CWE-787"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2021-45392httpd",
        post_binary_filename = "CVE-2021-45392httpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-45392httpd\CVE-2021-45392httpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-45392httpd\CVE-2021-45392httpd1_pseudo.c",
        cve_details="A Buffer Overflow vulnerability exists in Tenda Router AX12 V22.03.01.21_CN in page /goform/setIPv6Status via the prefixDelegate parameter, which causes a Denial of Service.",
        cwe="CWE-787"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2021-45733cstecgi",
        post_binary_filename = "CVE-2021-45733cstecgi1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-45733cstecgi\CVE-2021-45733cstecgi.cgi_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-45733cstecgi\CVE-2021-45733cstecgi1.cgi_pseudo.c",
        cve_details="TOTOLINK X5000R v9.1.0u.6118_B20201102 was discovered to contain a command injection vulnerability. This vulnerability allows attackers to execute arbitrary commands via the parameter host_time.",
        cwe="CWE-77"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2021-45737cstecgi",
        post_binary_filename = "CVE-2021-45737cstecgi1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-45737cstecgi\CVE-2021-45737cstecgi.cgi_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-45737cstecgi\CVE-2021-45737cstecgi1.cgi_pseudo.c",
        cve_details="TOTOLINK A720R v4.1.5cu.470_B20200911 was discovered to contain a stack overflow. This vulnerability allows attackers to cause a Denial of Service (DoS) via the Host parameter.",
        cwe="CWE-787"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2022-27374httpd",
        post_binary_filename = "CVE-2022-27374httpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2022-27374httpd\CVE-2022-27374httpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2022-27374httpd\CVE-2022-27374httpd1_pseudo.c",
        cve_details="Tenda AX12 V22.03.01.21_CN was discovered to contain a Cross-Site Request Forgery (CSRF) at /goform/SysToolReboot.",
        cwe="CWE-352"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2022-36480cstecgi",
        post_binary_filename = "CVE-2022-36480cstecgi1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2022-36480cstecgi\CVE-2022-36480cstecgi.cgi_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2022-36480cstecgi\CVE-2022-36480cstecgi1.cgi_pseudo.c",
        cve_details="TOTOLINK N350RT V9.3.5u.6139_B20201216 was discovered to contain a command injection vulnerability via the FileName parameter ",
        cwe="CWE-78"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2022-37083cstecgi",
        post_binary_filename = "CVE-2022-37083cstecgi1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2022-37083cstecgi\CVE-2022-37083cstecgi.cgi_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2022-37083cstecgi\CVE-2022-37083cstecgi1.cgi_pseudo.c",
        cve_details="TOTOLINK A7000R V9.1.0u.6115_B20201022 was discovered to contain a command injection vulnerability via the ip parameter ",
        cwe="CWE-78"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2022-37292httpd",
        post_binary_filename = "CVE-2022-37292httpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2022-37292httpd\CVE-2022-37292httpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2022-37292httpd\CVE-2022-37292httpd1_pseudo.c",
        cve_details="Tenda AX12 V22.03.01.21_CN is vulnerable to Buffer Overflow. This overflow is triggered in the function, which satisfies the request of the upper-level interface function that is, handles the post request",
        cwe="CWE-787"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2022-42167httpd",
        post_binary_filename = "CVE-2022-42167httpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2022-42167httpd\CVE-2022-42167httpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2022-42167httpd\CVE-2022-42167httpd1_pseudo.c",
        cve_details="Tenda AC10 V15.03.06.23 contains a Stack overflow vulnerability ",
        cwe="CWE-787"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2023-27012httpd",
        post_binary_filename = "CVE-2023-27012httpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2023-27012httpd\CVE-2023-27012httpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2023-27012httpd\CVE-2023-27012httpd1_pseudo.c",
        cve_details="Tenda AC10 US_AC10V4.0si_V16.03.10.13_cn was discovered to contain a stack overflow. This vulnerability allows attackers to cause a Denial of Service (DoS) or execute arbitrary code via a crafted payload.",
        cwe="CWE-787"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2023-33670httpd",
        post_binary_filename = "CVE-2023-33670httpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2023-33670httpd\CVE-2023-33670httpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2023-33670httpd\CVE-2023-33670httpd1_pseudo.c",
        cve_details="Tenda AC8V4.0-V16.03.34.06 was discovered to contain a stack overflow via the time parameter ",
        cwe="CWE-787"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2023-37171shttpd",
        post_binary_filename = "CVE-2023-37171shttpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2023-37171shttpd\CVE-2023-37171shttpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2023-37171shttpd\CVE-2023-37171shttpd1_pseudo.c",
        cve_details="TOTOLINK A3300R V17.0.0cu.557_B20221024 was discovered to contain a command injection vulnerability via the command parameter ",
        cwe="CWE-78"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2023-38937httpd",
        post_binary_filename = "CVE-2023-38937httpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2023-38937httpd\CVE-2023-38937httpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2023-38937httpd\CVE-2023-38937httpd1_pseudo.c",
        cve_details="Tenda AC10 V1.0 V15.03.06.23, AC1206 V15.03.06.23, AC8 v4 V16.03.34.06, AC6 V2.0 V15.03.06.23, AC7 V1.0 V15.03.06.44, AC5 V1.0 V15.03.06.28, AC9 V3.0 V15.03.06.42_multi and AC10 v4.0 V16.03.10.13 were discovered to contain a stack overflow via the list parameter ",
        cwe="CWE-787"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2023-46410shttpd",
        post_binary_filename = "CVE-2023-46410shttpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2023-46410shttpd\CVE-2023-46410shttpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2023-46410shttpd\CVE-2023-46410shttpd1_pseudo.c",
        cve_details="TOTOLINK X6000R v9.4.0cu.652_B20230116 was discovered to contain a remote command execution (RCE) vulnerability",
        cwe="CWE-77"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2023-46415shttpd",
        post_binary_filename = "CVE-2023-46415shttpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2023-46415shttpd\CVE-2023-46415shttpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2023-46415shttpd\CVE-2023-46415shttpd1_pseudo.c",
        cve_details="TOTOLINK X6000R v9.4.0cu.652_B20230116 was discovered to contain a remote command execution (RCE) vulnerability",
        cwe="CWE-77"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2023-46976shttpd",
        post_binary_filename = "CVE-2023-46976shttpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2023-46976shttpd\CVE-2023-46976shttpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2023-46976shttpd\CVE-2023-46976shttpd1_pseudo.c",
        cve_details="TOTOLINK A3300R 17.0.0cu.557_B20221024 contains a command injection via the file_name parameter ",
        cwe="CWE-787"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2023-4744httpd",
        post_binary_filename = "CVE-2023-4744httpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2023-4744httpd\CVE-2023-4744httpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2023-4744httpd\CVE-2023-4744httpd1_pseudo.c",
        cve_details="A vulnerability was found in Tenda AC8 16.03.34.06_cn_TDC01. It has been declared as critical. The manipulation leads to stack-based buffer overflow. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-238633 was assigned to this vulnerability.",
        cwe="CWE-787"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2023-48799shttpd",
        post_binary_filename = "CVE-2023-48799shttpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2023-48799shttpd\CVE-2023-48799shttpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2023-48799shttpd\CVE-2023-48799shttpd1_pseudo.c",
        cve_details="In TOTOLINK X6000R_Firmware V9.4.0cu.852_B20230719, the vulnerable function obtains fields from the front-end, connects them through the snprintf function, and passes them to the CsteSystem function, resulting in a command execution vulnerability.",
        cwe="CWE-78"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2023-52040shttpd",
        post_binary_filename = "CVE-2023-52040shttpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2023-52040shttpd\CVE-2023-52040shttpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2023-52040shttpd\CVE-2023-52040shttpd1_pseudo.c",
        cve_details="An issue discovered in TOTOLINK X6000R v9.4.0cu.852_B20230719 allows attackers to run arbitrary commands.",
        cwe="CWE-78"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2024-39226s2s",
        post_binary_filename = "CVE-2024-39226s2s1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2024-39226s2s\CVE-2024-39226s2s.so_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2024-39226s2s\CVE-2024-39226s2s1.so_pseudo.c",
        cve_details="GL-iNet products AR750/AR750S/AR300M/AR300M16/MT300N-V2/B1300/MT1300/SFT1200/X750 v4.3.11, MT3000/MT2500/AXT1800/AX1800/A1300/X300B v4.5.16, XE300 v4.3.16, E750 v4.3.12, AP1300/S1300 v4.3.13, and XE3000/X3000 v4.4 were discovered to contain a vulnerability can be exploited to manipulate routers by passing malicious shell commands through the s2s API.",
        cwe="CWE-22"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2024-57011cstecgi",
        post_binary_filename = "CVE-2024-57011cstecgi1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2024-57011cstecgi\CVE-2024-57011cstecgi.cgi_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2024-57011cstecgi\CVE-2024-57011cstecgi1.cgi_pseudo.c",
        cve_details="TOTOLINK X5000R V9.1.0cu.2350_B20230313 was discovered to contain an OS command injection vulnerability",
        cwe="CWE-78"
    ))
''' 
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2024-57020cstecgi",
        post_binary_filename = "CVE-2024-57020cstecgi1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2024-57020cstecgi\CVE-2024-57020cstecgi.cgi_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2024-57020cstecgi\CVE-2024-57020cstecgi1.cgi_pseudo.c",
        cve_details="TOTOLINK X5000R V9.1.0cu.2350_B20230313 was discovered to contain an OS command injection vulnerability",
        cwe="CWE-78"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2025-5502boa",
        post_binary_filename = "CVE-2025-5502boa1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2025-5502boa\CVE-2025-5502boa_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2025-5502boa\CVE-2025-5502boa1_pseudo.c",
        cve_details="A vulnerability, which was classified as critical, was found in TOTOLINK X15 1.0.0-B20230714.1105. This affects the function.The manipulation of the argument deviceMacAddr leads to stack-based buffer overflow. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.",
        cwe="CWE-787"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2020-8423httpd",
        post_binary_filename = "CVE-2020-8423httpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2020-8423httpd\CVE-2020-8423httpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2020-8423httpd\CVE-2020-8423httpd1_pseudo.c",
        cve_details="A buffer overflow in the httpd daemon on TP-Link TL-WR841N V10 (firmware version 3.16.9) devices allows an authenticated remote attacker to execute arbitrary code via a GET request to the page for the configuration of the Wi-Fi network.",
        cwe="CWE-120"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2022-30024httpd",
        post_binary_filename = "CVE-2022-30024httpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2022-30024httpd\CVE-2022-30024httpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2022-30024httpd\CVE-2022-30024httpd1_pseudo.c",
        cve_details="A buffer overflow in the httpd daemon on TP-Link TL-WR841N V12 (firmware version 3.16.9) devices allows an authenticated remote attacker to execute arbitrary code via a GET request to the page for the System Tools of the Wi-Fi network. This affects TL-WR841 V12 TL-WR841N(EU)_V12_160624 and TL-WR841 V11 TL-WR841N(EU)_V11_160325 , TL-WR841N_V11_150616 and TL-WR841 V10 TL-WR841N_V10_150310 are also affected.",
        cwe="CWE-120"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2021-35325lighttpd",
        post_binary_filename = "CVE-2021-35325lighttpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-35325lighttpd\CVE-2021-35325lighttpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-35325lighttpd\CVE-2021-35325lighttpd1_pseudo.c",
        cve_details="A stack overflow in the function of TOTOLINK A720R A720R_Firmware v4.1.5cu.470_B20200911 allows attackers to cause a denial of service (DOS).",
        cwe="CWE-787"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2025-51630cstecgi",
        post_binary_filename = "CVE-2025-51630cstecgi1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2025-51630cstecgi\CVE-2025-51630cstecgi.cgi_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2025-51630cstecgi\CVE-2025-51630cstecgi1.cgi_pseudo.c",
        cve_details="TOTOLINK N350RT V9.3.5u.6139_B20201216 was discovered to contain a buffer overflow via the ePort parameter",
        cwe="CWE-120"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2017-13772httpd",
        post_binary_filename = "CVE-2017-13772httpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2017-13772httpd\CVE-2017-13772httpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2017-13772httpd\CVE-2017-13772httpd1_pseudo.c",
        cve_details="Multiple stack-based buffer overflows in TP-Link WR940N WiFi routers with hardware version 4 allow remote authenticated users to execute arbitrary code via the (1) ping_addr parameter to PingIframeRpm.htm or (2) dnsserver2 parameter to WanStaticIpV6CfgRpm.htm.",
        cwe="CWE-119"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2021-45734cstecgi",
        post_binary_filename = "CVE-2021-45734cstecgi1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-45734cstecgi\CVE-2021-45734cstecgi.cgi_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-45734cstecgi\CVE-2021-45734cstecgi1.cgi_pseudo.c",
        cve_details="TOTOLINK X5000R v9.1.0u.6118_B20201102 was discovered to contain a command injection vulnerability in the function UploadFirmwareFile. This vulnerability allows attackers to execute arbitrary commands",
        cwe="CWE-121"
    ))
'''
'''
if __name__ == "__main__":
    asyncio.run(main(
        chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2021-45742cstecgi",
        post_binary_filename = "CVE-2021-45742cstecgi1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-45742cstecgi\CVE-2021-45742cstecgi.cgi_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2021-45742cstecgi\CVE-2021-45742cstecgi1.cgi_pseudo.c",
        cve_details="TOTOLINK A720R v4.1.5cu.470_B20200911 was discovered to contain a command injection vulnerability. This vulnerability allows attackers to execute arbitrary commands via the QUERY_STRING parameter.",
        cwe="CWE-77"
    ))
'''
