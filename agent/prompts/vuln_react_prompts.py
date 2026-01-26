# -*- coding: utf-8 -*-
"""
ReAct Agent 提示词模板

用于漏洞分析的 LangChain ReAct Agent 系统提示词和模板
"""

# ReAct Agent 系统提示词
VULN_REACT_SYSTEM_PROMPT = """You are an expert security analyst specialized in binary vulnerability analysis. Your task is to analyze IDA-decompiled pseudo-C code from two binary versions (before and after a patch) to determine if there is a genuine security vulnerability.

## Your Mission
Analyze the provided function pair and determine:
1. Whether a security vulnerability exists in the "before" version
2. Whether the "after" version properly fixes the vulnerability
3. Provide detailed evidence for your conclusion

## Analysis Methodology
You must follow a systematic approach:
1. **Initial Code Review**: First examine the provided function code to understand its purpose
2. **Identify Security-Relevant Operations**: Look for dangerous operations (memory operations, command execution, etc.)
3. **Trace Data Flow**: When you see potentially dangerous operations, trace where the data comes from
4. **Check Input Controllability**: Determine if attacker-controlled data can reach dangerous sinks
5. **Verify Fix**: If a vulnerability exists, check if the patch properly addresses it

## Key Security Patterns to Look For
- **Command Injection (CWE-78)**: system(), popen(), exec*() with user input
- **Buffer Overflow (CWE-120/121/122)**: strcpy, sprintf, memcpy without bounds checking
- **Format String (CWE-134)**: printf family with user-controlled format string
- **Path Traversal (CWE-22)**: File operations with unsanitized paths
- **Integer Overflow (CWE-190)**: Arithmetic operations that may overflow

## When to Request More Context
You SHOULD request additional context when:
1. A parameter's origin is unclear - use `get_callers` to see how this function is called
2. A called function's behavior is unclear - use `get_function_body` to examine it
3. You need to understand the call chain - use `get_callees` to see what functions are called
4. Data flow is complex - use `get_data_flow` to trace variable sources

You should NOT request context for:
- Standard library functions with well-known behavior (strlen, memset, etc.)
- Obvious non-security-relevant code (logging, UI updates, etc.)

## Output Requirements
When you have gathered sufficient information, provide your final analysis using the `submit_analysis` tool with:
1. Whether a vulnerability exists (vulnerability_found: Yes/No)
2. Vulnerability details if found (type, severity, location)
3. Fix analysis (is_fixed: Yes/No/Partial)
4. Detailed reasoning with evidence

Remember: Quality over quantity. It's better to request relevant context than to make assumptions."""

# ReAct Agent Human 提示词模板
VULN_REACT_HUMAN_PROMPT = """## Vulnerability Analysis Task

**Vulnerability Type**: {vulnerability_type}
**CWE ID**: {cwe_id}

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

### Your Task
Analyze this function pair to determine:
1. Does the BEFORE version contain a {vulnerability_type} vulnerability?
2. Does the AFTER version properly fix it?
3. What is your confidence level and reasoning?

You may use the available tools to gather more context about:
- Caller functions (to understand input sources)
- Called functions (to understand behavior)
- Data flow (to trace variable origins)

**IMPORTANT**: 
- Avoid repeatedly calling the same tool with identical parameters
- Once you have gathered sufficient evidence (typically 5-8 tool calls), use `submit_analysis` to provide your conclusion
- If you're unsure after gathering context, it's better to submit your analysis with lower confidence than to keep searching indefinitely

When you have sufficient information, use the `submit_analysis` tool to provide your final verdict."""

# 工具描述
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
Output: Data flow chains showing variable sources and sinks""",

    "submit_analysis": """Submit your final vulnerability analysis.

Use this tool ONLY when you have gathered sufficient information to make a confident assessment.

Input: A complete analysis result including:
- vulnerability_found: Yes/No
- vulnerability_type: CWE ID
- severity: High/Medium/Low/None
- is_fixed: Yes/No/Partial
- detailed reasoning"""
}

# Few-shot 示例
FEW_SHOT_EXAMPLES = [
    {
        "scenario": "Command Injection Analysis",
        "thought_process": """
Thought: I see a call to `system()` in the function. Let me check what argument is passed to it.
Action: get_function_body
Action Input: {"function_name": "do_command"}
Observation: The function builds a command string using sprintf with user input.

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
    "is_fixed": "Yes",
    "root_cause": "User input from HTTP request passed directly to system() without sanitization",
    "fix_description": "The patch adds input validation and escapes special characters before command execution",
    "reason": ["HTTP parameter flows to sprintf then to system()", "No input validation in vulnerable version", "Patch adds proper escaping"]
}
"""
    },
    {
        "scenario": "Buffer Overflow Analysis",
        "thought_process": """
Thought: I see strcpy() being used. Let me check the destination buffer size and source.
Action: get_data_flow
Action Input: {"function_name": "process_name", "variable_name": "dest_buf"}
Observation: dest_buf is a stack buffer of 64 bytes, source comes from user input with no length check.

Thought: Let me verify the input source by checking callers.
Action: get_callers
Action Input: {"function_name": "process_name", "depth": 1}
Observation: Called from parse_request with the input parameter coming from network data.

Thought: I have enough evidence. This is a classic stack buffer overflow.
Action: submit_analysis
Action Input: {
    "vulnerability_found": "Yes",
    "vulnerability_type": "CWE-121",
    "severity": "High", 
    "is_fixed": "Yes",
    "root_cause": "Unbounded strcpy to fixed-size stack buffer with network input",
    "fix_description": "Changed strcpy to strncpy with proper length limit",
    "reason": ["64-byte stack buffer with strcpy from unbounded network input", "No length validation", "Patch uses strncpy with size limit"]
}
"""
    },
    {
        "scenario": "False Positive - Safe Code",
        "thought_process": """
Thought: I see a call to strcpy(). Let me analyze if it's actually dangerous.
Action: get_data_flow
Action Input: {"function_name": "init_config", "variable_name": "config_path"}
Observation: The source is a hardcoded string literal "/etc/app.conf".

Thought: The source is a compile-time constant, not user input. This is not exploitable.
Action: submit_analysis
Action Input: {
    "vulnerability_found": "No",
    "vulnerability_type": "CWE-120",
    "severity": "None",
    "is_fixed": "N/A",
    "root_cause": "N/A - strcpy source is a constant string literal, not user-controllable",
    "fix_description": "N/A",
    "reason": ["strcpy used with constant string literal source", "No user-controllable data flow to this operation", "Code change is unrelated to security"]
}
"""
    }
]

# 生成 few-shot 示例的格式化文本
def format_few_shot_examples():
    """格式化 few-shot 示例为文本"""
    examples_text = "\n## Example Analysis Scenarios\n\n"
    for i, example in enumerate(FEW_SHOT_EXAMPLES, 1):
        examples_text += f"### Example {i}: {example['scenario']}\n"
        examples_text += f"```\n{example['thought_process'].strip()}\n```\n\n"
    return examples_text


def format_cwe_repair_samples(cwe_id: str, num_positive: int = 2, num_negative: int = 2) -> str:
    """
    从 data/cwe_samples.json 加载并格式化 CWE 正反修复样例
    
    Args:
        cwe_id: CWE 类型（如 "CWE-78"）
        num_positive: 正例数量
        num_negative: 负例数量
        
    Returns:
        格式化后的样例文本
    """
    import os
    import json
    import random
    
    # 从 data/cwe_samples.json 加载（项目根目录下的 data 文件夹）
    # 路径: agent/prompts/ -> agent/ -> project_root/ -> data/
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    samples_file = os.path.join(project_root, "data", "cwe_samples.json")
    
    try:
        with open(samples_file, 'r', encoding='utf-8') as f:
            all_samples = json.load(f)
    except Exception as e:
        return f"[无法加载修复样例: {e}]"
    
    # 获取对应 CWE 的样例
    cwe_samples = all_samples.get(cwe_id, [])
    
    if not cwe_samples:
        # 如果没有对应的 CWE 样例，尝试使用类似 CWE 或返回通用提示
        return f"[暂无 {cwe_id} 的修复样例，请根据漏洞类型特征进行分析]"
    
    # 分离正负样例
    positive_samples = [s for s in cwe_samples if s.get('is_positive', False)]
    negative_samples = [s for s in cwe_samples if not s.get('is_positive', False)]
    
    # 随机选择
    selected_positive = random.sample(positive_samples, min(num_positive, len(positive_samples)))
    selected_negative = random.sample(negative_samples, min(num_negative, len(negative_samples)))
    
    # 格式化输出
    result_parts = []
    
    # 格式化正例（真正修复漏洞的样例）
    if selected_positive:
        result_parts.append("#### ✅ Positive Examples (Genuine Vulnerability Fixes)")
        result_parts.append("These examples show REAL vulnerabilities that were PROPERLY FIXED:\n")
        for i, sample in enumerate(selected_positive, 1):
            # cwe_samples.json 使用 'id' 字段作为标识（如 CVE-xxx）
            sample_id = sample.get('id', 'Unknown')
            sample_name = f"{sample.get('cwe', cwe_id)} - {sample_id}" if sample_id else sample.get('cwe', cwe_id)
            result_parts.append(f"**Example {i}: {sample_name}**")
            result_parts.append(f"```c\n// BEFORE (Vulnerable)\n{sample.get('before', '')}\n```")
            result_parts.append(f"```c\n// AFTER (Fixed)\n{sample.get('after', '')}\n```")
            result_parts.append(f"**Why this is a real fix**: {sample.get('rationale', '')}\n")
    
    # 格式化负例（非安全相关修改的样例）
    if selected_negative:
        result_parts.append("#### ❌ Negative Examples (Non-Security Changes)")
        result_parts.append("These examples show changes that are NOT security fixes - DO NOT report these as vulnerabilities:\n")
        for i, sample in enumerate(selected_negative, 1):
            sample_id = sample.get('id', 'Unknown')
            sample_name = f"{sample.get('cwe', cwe_id)} - {sample_id}" if sample_id else f"{sample.get('cwe', cwe_id)} - False Positive"
            result_parts.append(f"**Example {i}: {sample_name}**")
            result_parts.append(f"```c\n// BEFORE\n{sample.get('before', '')}\n```")
            result_parts.append(f"```c\n// AFTER\n{sample.get('after', '')}\n```")
            result_parts.append(f"**Why this is NOT a security fix**: {sample.get('rationale', '')}\n")
    
    return "\n".join(result_parts)


# 最终分析输出格式
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
        "data_flow_trace": "Key data flow paths identified",
        "dangerous_operations": "List of dangerous operations found",
        "input_sources": "Where controllable input enters"
    },
    "confidence": "High/Medium/Low",
    "reason": ["Detailed reasoning point 1", "Reasoning point 2", "..."]
}"""

# RAG 增强的完整提示词模板（用于生成最终判断）
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

## Real-World Repair Patterns (Learn from these)
{repair_samples}

## Your Task
Based on ALL the information above:
1. Determine if there is a genuine security vulnerability
2. Verify if the patch properly fixes it
3. Provide detailed evidence-based reasoning

## Output Format (strict JSON)
{output_format}

Remember:
- Consider the full data flow from sources to sinks
- Check if attacker-controlled input can reach dangerous operations
- Verify boundary conditions and input validation
- Compare before/after to confirm the fix addresses the root cause"""
