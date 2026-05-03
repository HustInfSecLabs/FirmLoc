# -*- coding: utf-8 -*-
"""
Prompt definitions for the vulnerability ReAct agent.
"""


VULN_REACT_SYSTEM_PROMPT = """You are an expert security analyst specialized in binary vulnerability analysis.

Core principles:
- Analyze the CURRENT function pair first and keep conclusions grounded in this pair.
- Use tools only to clarify data origin, sink behavior, or patch behavior that is still unclear.
- Never jump to unrelated functions. Every extra function you inspect must come from a prior observation.
- Do not borrow evidence from another candidate function and apply it to the current function.
- Judge the function against the requested CWE/vulnerability type. If the evidence more strongly matches a different bug class, do not force the current CWE; instead treat the current CWE scenario as not matched.
- If a parameter origin is unclear, trace it upward through direct callers until you can decide whether the vulnerable parameter is attacker-controllable.
- Stop tracing when you reach a clear external input source, a constant/hardcoded source, or a function you have already fully analyzed.
- If a validation helper or sanitizer is observed but its body cannot be found, do not keep blindly searching for similarly named functions; reason from the observed call site and surrounding evidence instead.

Output principles:
- Submit conclusions only with `submit_analysis`.
- `data_flow_trace` must be a concrete `->` propagation chain supported by the observed evidence.
- Prefer exact function names, parameter names, locals, fields, helpers, and sink calls over vague summaries.
- Include only steps supported by evidence; do not invent missing hops."""


VULN_REACT_HUMAN_PROMPT = """## Vulnerability Analysis Task

**Vulnerability Type**: {vulnerability_type}
**CWE ID**: {cwe_id}

### Current Target Function Pair
- BEFORE function: {pre_function_name}
- AFTER function: {post_function_name}

### CVE/CWE Description
{cve_details}

### Real-World Repair Patterns (MUST Learn From These)
{repair_samples}

### Function Code - BEFORE Patch
```c
{code_before}
```

### Function Code - AFTER Patch
```c
{code_after}
```

**IMPORTANT**:
- Keep the analysis centered on the current target function pair: `{pre_function_name}`
- Your first tool call MUST target `{pre_function_name}`
- If `get_data_flow` identifies a suspicious sink, prefer `get_sink_slice` before exploring more functions
- Only inspect other functions if they are directly related callers/callees of the target pair, or are required to trace a specific variable discovered from the target pair
- Do NOT analyze unrelated functions or jump to arbitrary suspicious functions without a direct relationship to the target pair
- If the evidence points more strongly to a different bug class than `{vulnerability_type}`, do not relabel it as `{vulnerability_type}`; set `scenario_match` to `No` instead
- If you call a tool on another function, the function must come from a prior observation about the target pair
- If a validation helper or sanitizer name is observed but its body cannot be found, do not continue blind searching for similarly named functions; reason from the observed call site instead
- Do not mention CVE root function, attack-chain role, binding_reason, or dataflow_evidence in the submitted result
- In `data_flow_trace`, write a concrete `->` chain with exact names from the code or tool observations whenever possible
- If `get_sink_slice` was used, prefer its `local_data_flow_trace` as the core of `data_flow_trace`
- Only prepend caller-side provenance from `get_callers` / `get_function_body` when that extra prefix is directly supported by observations
- Do NOT submit vague summaries like "memory operations", "index calculations", or "environment variables" if more concrete steps are available
- Avoid repeatedly calling the same tool with identical parameters
- Once you have gathered sufficient evidence, use `submit_analysis`"""


TOOL_DESCRIPTIONS = {
    "get_function_body": """Retrieve the complete pseudo-C code of a specific function from the binary.

Use this tool when:
- You need to understand what a called function does
- You want to examine a function's implementation details
- You need to check how a function handles its parameters

Input: function_name (str) - The name of the function to retrieve
Output: The complete decompiled C-like pseudocode of the function""",

    "get_callers": """Get all functions that call a specific function (upstream analysis).

Use this tool when:
- You need to understand how a function is called
- You want to trace where function parameters come from
- You need to determine if user input can reach a function

Input: function_name (str), depth (int, optional) - Max recursion depth (default: 2)
Output: List of caller functions with their call contexts""",

    "get_callees": """Get all functions called by a specific function (downstream analysis).

Use this tool when:
- You need to understand what a function does internally
- You want to find dangerous operations within a function
- You need to trace data flow to dangerous sinks

Input: function_name (str), depth (int, optional) - Max recursion depth (default: 2)
Output: List of called functions""",

    "get_data_flow": """Get data flow analysis for a specific parameter or variable.

Use this tool when:
- You need to trace where a variable's value comes from
- You want to determine if a value is user-controllable
- You need to understand how data propagates through the function

Input: function_name (str), variable_name (str, optional)
Output: Concrete data flow chains showing variable sources, intermediate hops, and sinks""",

    "get_sink_slice": """Get a sink-anchored backward slice for one suspicious sink in the current function.

Use this tool when:
- get_data_flow has already identified a concrete suspicious sink
- You want a cleaner local path focused on that sink only
- You need control dependencies and source candidates for one sink

Input: function_name (str), sink_expression (str, optional), sink_name (str, optional), sink_line_hint (str, optional), variable_name (str, optional), emit_slice_code (bool, optional)
Output: A local sink-centered slice summary including tracked vars, control dependencies, and local_data_flow_trace""",

    "submit_analysis": """Submit your final vulnerability analysis.

Use this tool ONLY when you have gathered sufficient information to make a confident assessment.

Input: A complete analysis result including:
- vulnerability_found: Yes/No
- vulnerability_type: CWE ID
- severity: High/Medium/Low/None
- vulnerable_code_location: where the vulnerable operation exists in the current function
- attack_vector: how exploitation would occur
- impact: potential impact
- is_fixed: Yes/No/Partial
- data_flow_trace: current-function data flow only, written as a concrete `->` propagation chain using exact names where possible
- dangerous_operations: dangerous operations in the current function
- input_sources: controllable inputs in the current function
- detailed reasoning"""
}


FEW_SHOT_EXAMPLES = [
    {
        "scenario": "Command Injection Analysis",
        "thought_process": """
Thought: I see a call to `system()` in the function. Let me check what argument is passed to it.
Action: get_data_flow
Action Input: {"function_name": "do_command", "version": "pre"}
Observation: The function builds a command string using sprintf with user input and passes it to system().

Thought: I should refine the sink-centered path around system().
Action: get_sink_slice
Action Input: {"function_name": "do_command", "version": "pre", "sink_name": "system", "sink_expression": "system(cmd)"}
Observation: Local data flow trace is user_input -> sprintf(cmd, ...) -> system(cmd).

Thought: I need to check where the input comes from. Let me look at the callers.
Action: get_callers
Action Input: {"function_name": "do_command", "depth": 2}
Observation: The function is called from handle_request which receives HTTP parameters.

Thought: Now I have enough information. The user input flows from HTTP request to system() without sanitization.
Action: submit_analysis
Action Input: {
    "vulnerability_found": "Yes",
    "vulnerability_type": "CWE-78",
    "severity": "High",
    "vulnerable_code_location": "Command string construction and system execution in the current function",
    "attack_vector": "Remote attacker supplies crafted HTTP parameter that reaches command execution",
    "impact": "Arbitrary command execution",
    "is_fixed": "Yes",
    "data_flow_trace": "HTTP parameter -> sprintf -> system()",
    "dangerous_operations": "sprintf, system",
    "input_sources": "HTTP request parameter",
    "root_cause": "User input from HTTP request passed directly to system() without sanitization",
    "fix_description": "The patch adds input validation and escapes special characters before command execution",
    "reason": ["HTTP parameter flows to sprintf then to system()", "No input validation in vulnerable version", "Patch adds proper escaping"]
}
"""
    },
]


def format_few_shot_examples():
    """Format few-shot examples into prompt text."""
    examples_text = "\n## Example Analysis Scenarios\n\n"
    for i, example in enumerate(FEW_SHOT_EXAMPLES, 1):
        examples_text += f"### Example {i}: {example['scenario']}\n"
        examples_text += f"```\n{example['thought_process'].strip()}\n```\n\n"
    return examples_text


def format_cwe_repair_samples(cwe_id: str, num_positive: int = 1, num_negative: int = 1) -> str:
    """
    Load positive/negative repair samples for a CWE from data/cwe_samples.json.
    """
    import os
    import json
    import random

    project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    samples_file = os.path.join(project_root, "data", "cwe_samples.json")

    try:
        with open(samples_file, "r", encoding="utf-8") as f:
            all_samples = json.load(f)
    except Exception as e:
        return f"[Failed to load repair samples: {e}]"

    cwe_samples = all_samples.get(cwe_id, [])
    if not cwe_samples:
        return f"[No repair samples found for {cwe_id}]"

    positive_samples = [s for s in cwe_samples if s.get("is_positive", False)]
    negative_samples = [s for s in cwe_samples if not s.get("is_positive", False)]

    selected_positive = random.sample(positive_samples, min(num_positive, len(positive_samples)))
    selected_negative = random.sample(negative_samples, min(num_negative, len(negative_samples)))

    result_parts = []

    if selected_positive:
        result_parts.append("#### Positive Examples (Genuine Vulnerability Fixes)")
        result_parts.append("These examples show REAL vulnerabilities that were PROPERLY FIXED:\n")
        for i, sample in enumerate(selected_positive, 1):
            sample_id = sample.get("id", "Unknown")
            sample_name = f"{sample.get('cwe', cwe_id)} - {sample_id}" if sample_id else sample.get("cwe", cwe_id)
            result_parts.append(f"**Example {i}: {sample_name}**")
            result_parts.append(f"```c\n// BEFORE (Vulnerable)\n{sample.get('before', '')}\n```")
            result_parts.append(f"```c\n// AFTER (Fixed)\n{sample.get('after', '')}\n```")
            result_parts.append(f"**Why this is a real fix**: {sample.get('rationale', '')}\n")

    if selected_negative:
        result_parts.append("#### Negative Examples (Non-Security Changes)")
        result_parts.append("These examples show changes that are NOT security fixes - DO NOT report these as vulnerabilities:\n")
        for i, sample in enumerate(selected_negative, 1):
            sample_id = sample.get("id", "Unknown")
            sample_name = f"{sample.get('cwe', cwe_id)} - {sample_id}" if sample_id else f"{sample.get('cwe', cwe_id)} - False Positive"
            result_parts.append(f"**Example {i}: {sample_name}**")
            result_parts.append(f"```c\n// BEFORE\n{sample.get('before', '')}\n```")
            result_parts.append(f"```c\n// AFTER\n{sample.get('after', '')}\n```")
            result_parts.append(f"**Why this is NOT a security fix**: {sample.get('rationale', '')}\n")

    return "\n".join(result_parts)


ANALYSIS_OUTPUT_FORMAT = """{
    "vulnerability_found": "Yes/No",
    "scenario_match": "Yes/No",
    "property_match": "Yes/No",
    "vulnerability_type": "CWE-XXX",
    "severity": "High/Medium/Low/None",
    "vulnerable_code_location": "Description of where the vulnerability exists",
    "vulnerability_details": {
        "root_cause": "Explain the root cause of the vulnerability",
        "attack_vector": "How could this be exploited",
        "impact": "What is the potential impact"
    },
    "fix_analysis": {
        "is_fixed": "Yes/No/Partial",
        "fix_description": "How the newer version addresses the issue"
    },
    "evidence": {
        "data_flow_trace": "Concrete step-by-step `->` chain of the current-function data flow, using exact names where possible",
        "dangerous_operations": "List of dangerous operations found",
        "input_sources": "Where controllable input enters"
    },
    "confidence": "High/Medium/Low",
    "reason": ["Detailed reasoning point 1", "Reasoning point 2", "..."]
}"""


RAG_ENHANCED_PROMPT = """You are a security analyst performing a second-pass analysis with additional context.

## Task
Re-analyze this function pair with the gathered context information to make a final vulnerability determination.

## Original Analysis Identified Potential Issues
The initial analysis flagged this function pair for deeper review.

## Vulnerability Type
{vulnerability_type} ({cwe_id})

## CVE/CWE Context
{cve_details}

## Function Code - BEFORE Patch
```c
{code_before}
```

## Function Code - AFTER Patch
```c
{code_after}
```

## Gathered Context Information
{context_info}

## Requirements
- Keep the conclusion grounded in the current function pair.
- Use the gathered context only as supporting evidence.
- Prefer exact sources, sinks, and concrete `->` chains.
- Do not invent unsupported hops.
- Explain whether the patch removes the risky behavior in this function.
"""
