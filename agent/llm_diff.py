#!/usr/bin/env python3
import os
import re
import json
import subprocess
import tiktoken
import asyncio
import requests
import concurrent.futures
from openai import OpenAI
from pathlib import Path
import glob, time, random
from datetime import datetime
from typing import Any, Dict, List, Optional, Callable

from model import AgentModel
from log import logger
from agent.data_flow_utils import format_key_param_data_flow, format_vuln_context

# ReAct Agent 相关导入（延迟导入以避免循环依赖）
# from agent.vuln_react_agent import VulnReActAgent, VulnReActRefiner


# 读取漏洞类型对应的Scenario和Property的JSON文件路径
VULNERABILITY_SCENARIOS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'vulnerability_scenarios.json')

# 基础PROMPT模板（漏洞复现模式）
BASE_PROMPT = """You are a security analyst. Your task is to judge whether the provided IDA-decompiled pseudo-C code represents a {$vulnerability_type$} vulnerability and whether the patch removes it.

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

以下为真实应用场景:

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

# 漏洞挖掘模式的PROMPT模板
DISCOVERY_PROMPT = """You are a security analyst specializing in vulnerability discovery. Your task is to analyze the provided IDA-decompiled pseudo-C code changes and identify potential {$vulnerability_type$} vulnerabilities.

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

以下为真实应用场景:

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

# 调用链代码切片的默认配置
DEFAULT_DANGER_APIS = [
    "strcpy", "strncpy", "memcpy", "strcat", "sprintf", "snprintf", "gets",
    "system", "popen", "exec", "execve", "execl", "exece", "malloc", "free",
    "read", "write", "recv", "send", "socket", "bind", "accept", "strlcpy",
    "strncat"
]

# 触发切片窗口的默认行数
DEFAULT_SLICE_BEFORE = 60
DEFAULT_SLICE_AFTER = 60

# 生成Scenario和Property的提示词
GENERATE_SCENARIO_PROMPT = """You are a security expert. Please generate a scenario and property for the given vulnerability type.

Vulnerability Type: {$vulnerability_type$}

A scenario should describe the conditions under which the vulnerability exists, in a format that can be answered with "Yes" or "No".
A property should describe the conditions under which a patch effectively fixes the vulnerability, also in a format that can be answered with "Yes" or "No".

Please provide your response in JSON format with the following structure:
{{
  "scenario": "[Your scenario description]",
  "property": "[Your property description]"
}}
"""

SUMMARY_PROMPT = """
你是一个漏洞分析结果的总结助手。
请根据以下漏洞分析结果，生成一个简洁的总结报告。

[漏洞分析结果]
{$result$}
[漏洞分析结果 end]

"""


async def async_gpt_inference(
    prompt: str,
    temperature: float = 0,
    max_tokens: int = 4096,
    default_system_prompt: str = "You are a helpful assistant."
) -> str:
    """异步版本的gpt_inference函数，避免阻塞事件循环"""
    # 创建一个执行器来运行同步的gpt_inference函数
    loop = asyncio.get_running_loop()
    try:
        # 使用默认的执行器，避免每次创建新的ThreadPoolExecutor
        result = await loop.run_in_executor(
            None,
            lambda: gpt_inference(prompt=prompt, temperature=temperature, default_system_prompt=default_system_prompt)
        )
        # 确保返回的是字符串类型
        if isinstance(result, str):
            return result
        else:
            # 如果不是字符串，转换为字符串
            return str(result)
    except asyncio.CancelledError:
        logger.warning("推理任务被取消")
        raise
    except Exception as e:
        logger.error(f"异步推理失败: {e}")
        return f"异步推理失败: {str(e)}"

def gpt_inference(prompt: str = None, temperature: int = 0, default_system_prompt: str = None, history: list = None):
    try:
        llm_diff_agent = AgentModel(model="DeepSeek")
        
        system_prompt = "You are a helpful security assistant." if default_system_prompt == None else default_system_prompt
        messages = [{"role": "system", "content": system_prompt}]
        # 使用None作为默认值，然后在函数内部创建空列表，避免可变默认参数问题
        history = history or []
        for his in history:
            # 安全地解包历史记录中的问答对
            if isinstance(his, tuple) and len(his) == 2:
                q, a = his
                messages.append({"role": "user", "content": q})
                messages.append({"role": "assistant", "content": a})
            else:
                logger.warning(f"历史记录格式不正确: {his}")
        messages.append({"role": "user", "content": prompt})
        result = llm_diff_agent.chat(prompt=prompt)

        return result
    except Exception as e:
        logger.error(f"大模型推理失败: {e}")
        return f"大模型推理失败: {str(e)}"

# 加载漏洞类型对应的Scenario和Property
def load_vulnerability_scenarios():
    """加载漏洞类型对应的Scenario和Property"""
    if not os.path.exists(VULNERABILITY_SCENARIOS_FILE):
        return {}
    
    try:
        with open(VULNERABILITY_SCENARIOS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"加载漏洞场景文件失败: {e}")
        return {}

# 保存漏洞类型对应的Scenario和Property
def save_vulnerability_scenarios(scenarios):
    """保存漏洞类型对应的Scenario和Property"""
    try:
        with open(VULNERABILITY_SCENARIOS_FILE, 'w', encoding='utf-8') as f:
            json.dump(scenarios, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        logger.error(f"保存漏洞场景文件失败: {e}")
        return False

# 生成指定漏洞类型的Scenario和Property
def generate_vulnerability_scenario(vulnerability_type):
    """生成指定漏洞类型的Scenario和Property"""
    prompt = GENERATE_SCENARIO_PROMPT.replace("{$vulnerability_type$}", vulnerability_type)
    
    try:
        result = gpt_inference(
            prompt=prompt,
            temperature=0,
            default_system_prompt="You are a security expert who can generate accurate vulnerability scenarios and properties."
        )
        
        # 解析生成的JSON结果
        scenario_data = json.loads(result)
        return scenario_data
    except Exception as e:
        logger.error(f"生成漏洞场景失败: {e}")
        return None

# 获取指定漏洞类型的Scenario和Property
def get_vulnerability_scenario(vulnerability_type):
    """获取指定漏洞类型的Scenario和Property，如果不存在则生成并保存"""
    scenarios = load_vulnerability_scenarios()
    
    # 检查是否已存在该漏洞类型的Scenario和Property
    if vulnerability_type in scenarios:
        return scenarios[vulnerability_type]
    
    # 如果不存在，则生成新的Scenario和Property
    scenario_data = generate_vulnerability_scenario(vulnerability_type)
    if scenario_data:
        # 将生成的Scenario和Property添加到JSON文件中
        scenarios[vulnerability_type] = scenario_data
        save_vulnerability_scenarios(scenarios)
        return scenario_data
    
    return None

# 从cwe_samples.json加载漏洞修复样例
def load_cwe_samples(samples_path=None):
    """加载CWE漏洞修复样例数据"""
    # 如果未提供路径，使用默认路径
    if samples_path is None:
        # 将默认路径固定为 "../data/cwe_samples.json"（相对于本文件所在目录）
        samples_path = os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "data", "cwe_samples.json")
        )
        if not os.path.exists(samples_path):
            logger.warning(f"无法找到cwe_samples.json文件，默认路径: {samples_path}")
            return {}
    
    try:
        with open(samples_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"加载cwe_samples.json失败: {e}")
        return {}

# 根据CWE类型选择正负样例
def select_cwe_samples(cwe_type, samples, num_positive=2, num_negative=2):
    """根据CWE类型选择指定数量的正负样例"""
    cwe_samples = samples.get(cwe_type, [])
    if not cwe_samples:
        logger.warning(f"未找到{cwe_type}类型的样例")
        return [], []
    
    # 分离正负样例
    positive_samples = [s for s in cwe_samples if s.get('is_positive', False)]
    negative_samples = [s for s in cwe_samples if not s.get('is_positive', False)]
    
    # 随机选择指定数量的样例
    selected_positive = random.sample(positive_samples, min(num_positive, len(positive_samples)))
    selected_negative = random.sample(negative_samples, min(num_negative, len(negative_samples)))
    
    return selected_positive, selected_negative

# 格式化样例为PROMPT格式
def format_samples_for_prompt(positive_samples, negative_samples):
    """将样例格式化为PROMPT所需的格式"""
    prompt_parts = []
    
    # 添加正例
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
    
    # 添加负例
    if negative_samples:
        prompt_parts.append("\n\n### Examples of False Fixes (Negative)")
        for i, sample in enumerate(negative_samples, 1):
            prompt_parts.append(f"{i}. [False Fix]")
            prompt_parts.append(f"Before: {sample.get('before', '')}")
            prompt_parts.append(f"After:  {sample.get('after', '')}")
            prompt_parts.append(f"Rationale: {sample.get('rationale', '')}")
            prompt_parts.append(f"(is_positive = false)")
    
    return "\n".join(prompt_parts)

# ———— Token计数和智能总结相关函数 ————
def count_tokens(text: str, model: str = "gpt-4") -> int:
    """计算文本的token数量"""
    try:
        encoding = tiktoken.encoding_for_model(model)
        return len(encoding.encode(text))
    except Exception as e:
        logger.warning(f"Token计数失败，使用近似估算: {e}")
        # 粗略估算：1 token ≈ 4个字符（对于英文）或1.5个字符（对于中文）
        # 使用保守估计
        return len(text) // 2

def extract_vulnerability_entries(results: str) -> List[Dict[str, Any]]:
    """从分析结果中提取各个漏洞条目，并解析评分"""
    entries = []
    # 按分隔符切分
    sections = re.split(r'===\s+(.+?\.c)\s+vs\s+(.+?\.c)\s+===', results)
    
    for i in range(1, len(sections), 3):
        if i + 1 < len(sections):
            pre_file = sections[i]
            post_file = sections[i + 1]
            content = sections[i + 2] if i + 2 < len(sections) else ""
            
            # 提取漏洞评分
            score = 0
            score_match = re.search(r'["\']?漏洞评分["\']?\s*[:：]\s*(\d+)', content, re.IGNORECASE)
            if score_match:
                score = int(score_match.group(1))
            
            # 提取是否为真实漏洞的判断
            is_vuln = False
            # 检查是否有明确的漏洞分析（RAG二次判断）
            if 'RAG二次判断' in content or '漏洞成因' in content:
                # 检查是否有明确的"无漏洞"或"非漏洞"判断
                if not re.search(r'(无漏洞|非漏洞|不是漏洞|false\s*fix)', content, re.IGNORECASE):
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
    """根据评分和重要性对条目进行优先级排序，返回高优先级和低优先级条目"""
    # 按评分降序排序
    sorted_entries = sorted(entries, key=lambda x: (x['score'], x['is_vuln']), reverse=True)
    
    high_priority = []
    low_priority = []
    current_tokens = 0
    
    # 计算SUMMARY_PROMPT的基础token数
    base_tokens = count_tokens(SUMMARY_PROMPT)
    available_tokens = max_tokens - base_tokens - 2000  # 留2000 token作为输出空间
    
    for entry in sorted_entries:
        entry_tokens = count_tokens(entry['content'])
        
        # 高分漏洞（>=7分）或确认的漏洞优先保留
        if entry['score'] >= 7 or entry['is_vuln']:
            if current_tokens + entry_tokens <= available_tokens:
                high_priority.append(entry)
                current_tokens += entry_tokens
            else:
                # 即使超出token限制，至少保留漏洞的摘要信息
                low_priority.append(entry)
        else:
            low_priority.append(entry)
    
    # 如果还有空间，添加中等分数的条目
    for entry in sorted_entries:
        if entry not in high_priority and entry not in low_priority:
            entry_tokens = count_tokens(entry['content'])
            if current_tokens + entry_tokens <= available_tokens:
                high_priority.append(entry)
                current_tokens += entry_tokens
            else:
                low_priority.append(entry)
    
    return high_priority, low_priority

def create_abbreviated_entry(entry: Dict[str, Any]) -> str:
    """为低优先级条目创建缩略信息"""
    return f"=== {entry['pre_file']} vs {entry['post_file']} ===\n" \
           f"[评分: {entry['score']}] [长度: {entry['length']} 字符]\n" \
           f"[摘要] 由于内容过长已省略，如需详细信息请查看完整日志\n\n"

async def generate_smart_summary(results: str, agent: str, send_message=None) -> str:
    """智能生成总结，处理token超限问题"""
    
    # 1. 提取所有漏洞条目
    entries = extract_vulnerability_entries(results)
    
    if not entries:
        logger.warning("未能从结果中提取到漏洞条目")
        return "分析完成，但未检测到明确的漏洞条目。"
    
    # 2. 计算总token数
    total_tokens = count_tokens(results)
    logger.info(f"分析结果总token数: {total_tokens}")
    
    # 3. 如果token数在安全范围内，直接生成总结
    if total_tokens < 60000:  # 给模型留足够的输入空间
        summary_prompt = SUMMARY_PROMPT.replace("{$result$}", results)
        return await async_gpt_inference(
            prompt=summary_prompt,
            temperature=0,
            default_system_prompt="You are a security analysis summary assistant."
        )
    
    # 4. Token超限，使用智能策略
    logger.warning(f"分析结果token数({total_tokens})超出限制，启用智能总结策略")
    
    if send_message:
        await send_message(
            f"⚠️ 分析结果较多({len(entries)}个函数对)，正在进行智能总结...",
            "message",
            agent=agent
        )
    
    # 5. 对条目进行优先级排序和筛选
    high_priority, low_priority = prioritize_entries(entries)
    
    logger.info(f"高优先级条目: {len(high_priority)}, 低优先级条目: {len(low_priority)}")
    
    # 6. 构建总结输入
    summarized_results = []
    
    # 添加高优先级条目（完整内容）
    for entry in high_priority:
        summarized_results.append(f"=== {entry['pre_file']} vs {entry['post_file']} ===\n{entry['content']}\n")
    
    # 添加低优先级条目（缩略信息）
    if low_priority:
        summarized_results.append("\n=== 其他分析结果（已缩略） ===\n")
        for entry in low_priority:
            summarized_results.append(create_abbreviated_entry(entry))
    
    filtered_results = "\n".join(summarized_results)
    
    # 7. 如果筛选后仍然超限，则分批总结
    filtered_tokens = count_tokens(filtered_results)
    
    if filtered_tokens > 60000:
        logger.warning("筛选后仍超限，采用分批总结策略")
        return await batch_summarize(high_priority, low_priority, agent, send_message)
    
    # 8. 生成最终总结
    summary_prompt = SUMMARY_PROMPT.replace("{$result$}", filtered_results)
    final_summary = await async_gpt_inference(
        prompt=summary_prompt,
        temperature=0,
        default_system_prompt="You are a security analysis summary assistant."
    )
    
    # 9. 附加统计信息
    stats = f"\n\n📊 统计信息:\n" \
            f"- 总分析函数对: {len(entries)}\n" \
            f"- 高危漏洞(>=7分): {sum(1 for e in entries if e['score'] >= 7)}\n" \
            f"- 中危漏洞(4-6分): {sum(1 for e in entries if 4 <= e['score'] < 7)}\n" \
            f"- 低危漏洞(1-3分): {sum(1 for e in entries if 1 <= e['score'] < 4)}\n" \
            f"- 详细总结条目: {len(high_priority)}\n" \
            f"- 缩略显示条目: {len(low_priority)}"
    
    return final_summary + stats

async def batch_summarize(high_priority: List[Dict], low_priority: List[Dict], 
                         agent: str, send_message=None) -> str:
    """分批总结策略：将条目分成多个批次，分别总结后再汇总"""
    
    batch_size = 5  # 每批处理5个条目
    batch_summaries = []
    
    # 分批处理高优先级条目
    for i in range(0, len(high_priority), batch_size):
        batch = high_priority[i:i + batch_size]
        
        if send_message:
            await send_message(
                f"正在总结第 {i//batch_size + 1} 批条目 ({len(batch)} 个函数对)...",
                "message",
                agent=agent
            )
        
        batch_content = "\n".join([
            f"=== {e['pre_file']} vs {e['post_file']} ===\n{e['content']}\n"
            for e in batch
        ])
        
        batch_prompt = f"""请对以下漏洞分析结果进行简要总结：

{batch_content}

请关注：
1. 发现的主要漏洞类型
2. 漏洞的严重程度
3. 漏洞的成因和利用方式（如果有）
"""
        
        try:
            summary = await async_gpt_inference(
                prompt=batch_prompt,
                temperature=0,
                default_system_prompt="You are a security analysis summary assistant."
            )
            batch_summaries.append(f"### 批次 {i//batch_size + 1} 总结:\n{summary}")
        except Exception as e:
            logger.error(f"批次{i//batch_size + 1}总结失败: {e}")
            batch_summaries.append(f"### 批次 {i//batch_size + 1}: 总结失败")
    
    # 汇总所有批次
    final_prompt = f"""以下是分批次的漏洞分析总结，请生成一个综合性的最终总结报告：

{''.join(batch_summaries)}

低优先级条目统计：
- 共 {len(low_priority)} 个函数对未详细展示

请生成：
1. 整体漏洞情况概述
2. 主要发现的漏洞类型和严重程度
3. 关键风险点总结
4. 修复建议（如适用）
"""
    
    final_summary = await async_gpt_inference(
        prompt=final_prompt,
        temperature=0,
        default_system_prompt="You are a security analysis summary assistant."
    )
    
    # 添加统计信息
    all_entries = high_priority + low_priority
    stats = f"\n\n📊 统计信息:\n" \
            f"- 总分析函数对: {len(all_entries)}\n" \
            f"- 高危漏洞(>=7分): {sum(1 for e in all_entries if e['score'] >= 7)}\n" \
            f"- 中危漏洞(4-6分): {sum(1 for e in all_entries if 4 <= e['score'] < 7)}\n" \
            f"- 低危漏洞(1-3分): {sum(1 for e in all_entries if 1 <= e['score'] < 4)}\n" \
            f"- 分批总结数: {len(batch_summaries)}\n" \
            f"- 详细分析条目: {len(high_priority)}\n" \
            f"- 缩略显示条目: {len(low_priority)}"
    
    return final_summary + stats

# ———— 配置区 ————
def locate_paths(chat_id: str, history_root: str | Path, binary_filename: str) -> dict:

    history_root = Path(history_root).expanduser().resolve()
    """
    根据 chat_id 自动拼出相关目录 / 文件路径。
    返回 dict 用来替换原先的全局常量。
    """
    root     = history_root / chat_id
    ida_dir  = root / "ida"
    bd_dir   = root / "bindiff" /binary_filename

    logger.debug("DEBUG  bd_dir =")
    # print("DEBUG  items  =", [p.name for p in bd_dir.iterdir()])
    # matches = sorted(bd_dir.glob("*.results"))
    # print("DEBUG  matches=", [m.name for m in matches])

    # 1) work_dir = ida 目录
    work_dir = ida_dir

    # 2) pick first *.results ；如有多份可加别的策略
    matches = sorted(bd_dir.glob("*.results"))
    if not matches:
        raise FileNotFoundError(f"在 {bd_dir} 没找到 *.results")
    results_file = matches[0]

    # 3) output 子目录，用时间戳区分多次运行
    stamp       = time.strftime("%Y%m%d_%H%M%S")
    out_dir     = bd_dir / f"diff_{stamp}"
    folder_a    = out_dir / "folder_a"
    folder_b    = out_dir / "folder_b"
    log_file    = out_dir / "vuln_analysis_results.json"

    out_dir.mkdir(parents=True, exist_ok=True)

    return dict(
        WORK_DIR=str(work_dir),
        RESULTS_FILE=str(results_file),
        OUTPUT_DIR=str(out_dir),
        FOLDER_A=str(folder_a),
        FOLDER_B=str(folder_b),
        LOG_FILE=str(log_file)
    )
# BinDiff 导出结果
#RESULTS_FILE  = r"D:\HUSTCourse\402\chenyi_zhu\TestCase\httpd06_vs_httpd08.results"
# 切分后输出目录
#FOLDER_A      = r"D:\HUSTCourse\402\chenyi_zhu\TestCase\folder_a"
#FOLDER_B      = r"D:\HUSTCourse\402\chenyi_zhu\TestCase\folder_b"
# refiner 日志
#LOG_FILE      = r"D:\HUSTCourse\402\chenyi_zhu\TestCase\vuln_analysis_results.json"
# ————————————————

# 正则：匹配 bindiff 行并捕获相似度、函数名
res_pat = re.compile(
    r'^[0-9A-Fa-f]{8,16}\s+[0-9A-Fa-f]{8,16}\s+'
    r'(?P<sim>0\.\d+|1(?:\.0)?)\s+.*?"(?P<fn1>[^"]+)"\s*"(?P<fn2>[^"]+)"'
)

def demangle(mangled: str) -> str:
    """用 c++filt 解码并剥掉尾部参数编码。"""
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
        # 去掉常见尾部编码
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
            continue  # 完全相似不分析

        d1 = demangle(m.group("fn1"))  # 补丁前
        d2 = demangle(m.group("fn2"))  # 补丁后

        if d1.startswith("GLOBAL__sub_I") or d2.startswith("GLOBAL__sub_I"):
            continue
        mapping[d1] = d2  # 建立一一对应关系

    return mapping

import re

def split_functions(file_path):
    """
    扫描伪 C，识别所有函数 base name 及其完整文本区间（按大括号成对匹配）。
    返回 dict: base_name -> (start_idx, end_idx)。
    """
    sig_simple = re.compile(r'^[\w\*\s]+?([A-Za-z_]\w*)\s*\([^)]*\)\s*$')   # 只有函数声明（无{）
    sig_brace  = re.compile(r'^[\w\*\s]+?([A-Za-z_]\w*)\s*\([^)]*\)\s*\{')  # 函数声明直接带{

    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.read().splitlines(keepends=True)

    funcs = {}
    total = len(lines)
    i = 0

    while i < total:
        line = lines[i].strip()
        m = sig_brace.match(line) or (sig_simple.match(line) if (i+1 < total and lines[i+1].strip() == "{") else None)

        if m:
            func_name = m.group(1)
            start_idx = i

            # 如果当前行没有{，跳到下一行找
            if '{' not in line:
                i += 1

            brace_count = 0
            found_opening = False

            # 统计括号数量，直到匹配完成
            while i < total:
                brace_count += lines[i].count('{')
                brace_count -= lines[i].count('}')
                if lines[i].count('{'):
                    found_opening = True
                i += 1
                if found_opening and brace_count == 0:
                    break

            end_idx = i
            funcs[func_name] = (start_idx, end_idx)

        else:
            i += 1

    return funcs


def build_pseudo_index(pseudo_file: Optional[str]):
    """为伪C文件建立索引，返回 {file, lines, funcs}。"""
    if not pseudo_file or not os.path.exists(pseudo_file):
        logger.warning(f"伪C文件不存在，无法建立索引: {pseudo_file}")
        return None

    lines = open(pseudo_file, 'r', encoding='utf-8').read().splitlines(keepends=True)
    funcs = split_functions(pseudo_file)
    return {"file": pseudo_file, "lines": lines, "funcs": funcs}


def extract_call_chain(call_info: Dict[str, Any]) -> List[str]:
    """从 analyze 结果中提取调用链，优先使用显式字段，其次回退 callers。"""
    if not isinstance(call_info, dict):
        return []

    chain: List[str] = []

    def _clean(items: List[str]) -> List[str]:
        return [x for x in items if x and str(x).lower() not in {"<unknown>", "unknown"}]

    # 1) 显式字段
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

    # 2) 函数本身
    func_name = None
    func_obj = call_info.get("function") or {}
    if isinstance(func_obj, dict):
        func_name = func_obj.get("name")
    func_name = func_name or call_info.get("function_name")

    # 3) callers 结构（按地址排序，作为近似顺序）
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
    """从 data_flow/调用链信息中提取可用于定位的关键片段。"""
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

    # 简单去噪：长度>1 且裁剪空白
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
    """在索引中提取函数代码或切片。

    优先级：
      1) 数据流/调用链相关的高亮文本命中行
      2) 危险 API 命中行
      3) 头部窗口兜底
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
        # 1) 数据流/调用链高亮文本匹配
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

        # 2) 危险 API
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

        # 3) 头部兜底
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
    仅拆分 base_names 中的函数，并以 base_name.c 保存。
    """
    os.makedirs(out_dir, exist_ok=True)
    funcs = split_functions(pseudo_file)
    lines = open(pseudo_file,'r',encoding='utf-8').read().splitlines(keepends=True)
    for base in base_names:
        if base not in funcs:
            logger.warning(f"未找到函数 “{base}”")
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
        # ReAct Agent 相关参数
        use_react_agent: bool = True,
        pre_pseudo_file: Optional[str] = None,
        post_pseudo_file: Optional[str] = None,
    react_model_name: str = "DeepSeek",  # 对应 config.ini 中的 LLM.{model_name} 配置节
    react_max_iterations: int = 20,
        send_message: Optional[Callable] = None,
        history_dir: Optional[str] = None,
    ):
        self.log = LOG_FILE
        self.context_log = f"{LOG_FILE}.ctx"  # 将上下文单独存储，避免污染 vuln_analysis_results.json
        self.agent = "Detection Agent"
        self._task_cache = {}  # 初始化任务缓存字典
        self.pre_binary_name = pre_binary_name  # 保存补丁前二进制文件名
        self.post_binary_name = post_binary_name  # 保存补丁后二进制文件名

        # 调用链代码提取配置
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
        self.max_call_chain_chars = 100000  # 软限制，避免提示词过大
        
        # 二进制文件锁，防止对同一文件的并发 IDA 分析
        self._binary_locks = {}
        self._lock_access_lock = asyncio.Lock()  # 保护 _binary_locks 的访问
        
        # ReAct Agent 配置
        self.use_react_agent = use_react_agent
        self.pre_pseudo_file = pre_pseudo_file
        self.post_pseudo_file = post_pseudo_file
        self.react_model_name = react_model_name
        self.react_max_iterations = react_max_iterations
        self.send_message = send_message
        self.history_dir = history_dir
        
        # 延迟初始化 ReAct Agent（在需要时创建）
        self._react_refiner = None

    async def _get_lock_for_binary(self, binary_name):
        async with self._lock_access_lock:
            if binary_name not in self._binary_locks:
                self._binary_locks[binary_name] = asyncio.Lock()
            return self._binary_locks[binary_name]

        #api_key = "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"
        #if not api_key:
        #    raise RuntimeError("请先通过环境变量 OPENAI_API_KEY 设置你的 API Key")
        #self.client = OpenAI(api_key=api_key) 

    def make_prompt(self, fa_content, fb_content, cve_details=None, cwe=None, work_mode: str = "reproduction"):
        """生成分析提示词
        
        Args:
            fa_content: 补丁前代码内容
            fb_content: 补丁后代码内容
            cve_details: CVE详情（漏洞复现模式）或CWE描述（漏洞挖掘模式）
            cwe: CWE类型
            work_mode: 工作模式 - "reproduction"（漏洞复现）或 "discovery"（漏洞挖掘）
        """
        # 如果提供了cwe参数，获取对应的Scenario和Property
        scenario = ""
        property = ""
        vulnerability_type = cwe if cwe else "CWE-78"  # 默认使用CWE-78
        
        # 去除vulnerability_type中可能存在的双引号
        if vulnerability_type and (vulnerability_type.startswith('"') and vulnerability_type.endswith('"')):
            vulnerability_type = vulnerability_type[1:-1]
        
        if vulnerability_type:
            scenario_data = get_vulnerability_scenario(vulnerability_type)
            if scenario_data:
                scenario = scenario_data.get("scenario", "")
                property = scenario_data.get("property", "")
        
        # 根据工作模式选择不同的提示词模板
        if work_mode == "discovery":
            # 漏洞挖掘模式：使用 DISCOVERY_PROMPT
            prompt = DISCOVERY_PROMPT.replace("{$vulnerability_type$}", vulnerability_type)
            prompt = prompt.replace("{$cwe_id$}", vulnerability_type)
            prompt = prompt.replace("{$scenario$}", scenario)
            prompt = prompt.replace("{$property$}", property)
            prompt = prompt.replace("{$filea$}", fa_content)
            prompt = prompt.replace("{$fileb$}", fb_content)
            # 在挖掘模式下，cve_details 实际上是 CWE 的描述信息
            prompt = prompt.replace("{$result$}", "")  # 结果部分留空，由LLM填充
        else:
            # 漏洞复现模式：使用 BASE_PROMPT
            prompt = BASE_PROMPT.replace("{$vulnerability_type$}", vulnerability_type)
            prompt = prompt.replace("{$scenario$}", scenario)
            prompt = prompt.replace("{$property$}", property)
            prompt = prompt.replace("{$filea$}", fa_content)
            prompt = prompt.replace("{$fileb$}", fb_content)
            prompt = prompt.replace("{$cve_details$}", cve_details if cve_details else "")
        
        return prompt
        
    def make_rag_prompt(self, fa_content, fb_content, cve_details=None, cwe=None, pre_func_context=None, post_func_context=None, work_mode: str = "reproduction"):
        """生成带有RAG样例的提示词，包含函数调用链信息
        
        Args:
            fa_content: 补丁前代码内容
            fb_content: 补丁后代码内容
            cve_details: CVE详情（漏洞复现模式）或CWE描述（漏洞挖掘模式）
            cwe: CWE类型
            pre_func_context: 补丁前函数上下文
            post_func_context: 补丁后函数上下文
            work_mode: 工作模式 - "reproduction"（漏洞复现）或 "discovery"（漏洞挖掘）
        """
        # 设置默认值
        pre_func_context = pre_func_context or ""
        post_func_context = post_func_context or ""
        # 加载cwe_samples数据
        cwe_samples = load_cwe_samples()
        
        # 选择正负样例
        positive_samples, negative_samples = select_cwe_samples(cwe, cwe_samples)
        
        # 格式化样例
        samples_text = format_samples_for_prompt(positive_samples, negative_samples)
        
        # 构建完整的RAG提示词
        # 准备函数调用链信息
        context_info = ""
        if pre_func_context:
            context_info += f"\n5. 补丁前函数上下文信息：\n{pre_func_context}\n"
        if post_func_context:
            context_info += f"\n6. 补丁后函数上下文信息：\n{post_func_context}\n"
        
        rag_prompt = f"""
Your Task is to judge if the C-like pseudocode generate by IDA pro has vulnerability.
There are several context you can refer to:
1. {cve_details if cve_details else ""}
2. This vulnerability belongs to {cwe}.
3. You will be given the patched C-like psudeocode generated by IDA pro,
which means you can confirm suspected vulnerability according to the code change.
4. For each function pair analyzed, first determine if the changes are security-relevant according to the above criteria before including it in your report.
{context_info}

You MUST learn from the following real-world repair patterns:
{samples_text}

## INPUT FORMAT
[C-like pseudocode Before Code Change]
[filea]

[C-like pseudocode After Code Change]
[fileb]

## OUTPUT REQUIREMENTS
1. Provide a JSON response with ONLY functions containing genuine security-relevant changes.
2. For each function with security-relevant changes, include:
## 输出必须是合法 JSON（不要有其它字符）,
[差异分析]：
[漏洞类型]：
[漏洞成因]：说明具体的漏洞成因
[漏洞代码段]：将两个版本之间包含漏洞和修复漏洞的代码段指出
[函数功能]：简略描述这两段代码实现了什么功能，修改部分在函数整体当中的作用。
[漏洞利用方式]：如果不是修复漏洞则为无，否则详细说明可行的漏洞利用方式，如构造怎样的输入或变量可以实现攻击效果
[漏洞利用效果]：如果不是修复漏洞则为无，否则详细说明漏洞利用可能达到的攻击效果
[漏洞评分]：An integer of 1-10, 1-3 is classified as a minor vulnerability, such as using an insecure function printf, 4-6 is classified as a moderately dangerous vulnerability, and 7-10 is classified as a highly suspected vulnerability
3. If a function's changes are purely non-security-relevant (as defined in the IGNORE list), DO NOT include it in your output.

4. Begin your response with a summary stating: "I have analyzed X function pairs and identified Y functions with genuine security vulnerabilities."

Remember: Quality over quantity. It's better to correctly identify one genuine vulnerability than to report many false positives.


以下为真实应用场景:

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
        """调用IDA服务获取函数调用链信息"""
        # 获取该二进制文件的锁，确保串行访问
        lock = await self._get_lock_for_binary(binary_name)
        
        async with lock:
            try:
                # 调用app.py中的API端点
                url = "http://10.12.189.21:5000/get_function_call_info"
                data = {
                    "binary_name": binary_name,
                    "function_name": function_name,
                    "ida_version": "ida64"  # 使用64位IDA
                }
                
                # 由于这是一个异步函数，我们需要使用asyncio.to_thread来包装同步的requests调用
                loop = asyncio.get_event_loop()
                logger.info(f"调用 get_function_call_info | url={url} | bin={binary_name} func={function_name}")
                
                def _request():
                    try:
                        # 增加超时时间，因为可能需要等待IDA启动和分析
                        return requests.post(url, data=data, timeout=120)
                    except requests.exceptions.ConnectionError:
                        return None

                response = await loop.run_in_executor(None, _request)
                
                if response is None:
                    logger.error(f"无法连接到 IDA 服务: {url}")
                    return {}

                if response.status_code == 200:
                    # 期望返回结构应与 IDA 导出 JSON 一致，包含 data_flow 字段
                    # 这里不做结构转换，直接按原样返回，留给上层格式化时筛选关键字段
                    payload = response.json()
                    logger.debug(f"get_function_call_info 返回大小: {len(json.dumps(payload, ensure_ascii=False))} 字节")
                    return payload
                else:
                    logger.error(f"API调用失败，状态码: {response.status_code}")
                    logger.error(f"响应内容: {response.text}")
                    return {}
            except Exception as e:
                logger.error(f"API调用异常: {e}")
                return {}

    def _collect_call_chain_slices(self, call_info: Dict[str, Any], version_label: str):
        """基于调用链提取关键函数代码切片。"""
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
                lines.append("[提示] 调用链代码已截断，超出长度限制")
                break
        return "\n".join(lines).strip()
    
    # method removed; logic now resides in agent.data_flow_utils
    
        
    async def async_query2bot(self, fa, fb, cve_details=None, cwe=None, work_mode: str = "reproduction") -> str:
        """异步版本的query2bot函数
        
        Args:
            fa: 补丁前的伪C文件路径
            fb: 补丁后的伪C文件路径
            cve_details: CVE详情（漏洞复现模式）或CWE描述（漏洞挖掘模式）
            cwe: CWE类型
            work_mode: 工作模式 - "reproduction"（漏洞复现）或 "discovery"（漏洞挖掘）
        """
        logger.info(f"开始分析 {os.path.basename(fa)} vs {os.path.basename(fb)}, 工作模式: {work_mode}")
        
        # 检查缓存中是否已有结果
        cache_key = (os.path.basename(fa), os.path.basename(fb))
        if cache_key in self._task_cache:
            logger.info(f"从缓存获取 {os.path.basename(fa)} vs {os.path.basename(fb)} 的分析结果")
            return self._task_cache[cache_key]

        # 读两个.c文件的内容
        try:
            a_content = open(fa, 'r', encoding='utf-8').read()
            b_content = open(fb, 'r', encoding='utf-8').read()
        except Exception as e:
            logger.error(f"读取函数文件失败: {e}")
            return f"读取函数文件失败: {str(e)}"

        prompt = self.make_prompt(
            f"File: {os.path.basename(fa)}\n{a_content}",
            f"File: {os.path.basename(fb)}\n{b_content}",
            cve_details=cve_details,
            cwe=cwe,
            work_mode=work_mode
        )

        try:
            result = await async_gpt_inference(
                prompt=prompt,
                temperature=0,
                default_system_prompt="You are a security analysis assistant."
            )
        except Exception as e:
            logger.error(f"大模型推理失败: {e}")
            return f"大模型推理失败: {str(e)}"

        try:
            with open(self.log, 'a', encoding='utf-8') as w:
                w.write(f"=== {os.path.basename(fa)} vs {os.path.basename(fb)} ===\n")
                w.write(result + "\n\n")
            logger.info(f"写入分析结果到日志 {self.log}")
        except Exception as e:
            logger.error(f"写日志失败: {e}")
        
        # 检查是否需要进行二次判断
        need_rag = False
        # 优先尝试解析 JSON（容错：去掉 markdown 围栏/前后噪声，仅取花括号内容）
        if result:
            result_json = None
            try:
                s, e = result.find("{"), result.rfind("}")
                if s != -1 and e != -1 and e > s:
                    candidate = result[s:e+1]
                    result_json = json.loads(candidate)
                else:
                    result_json = json.loads(result)
            except Exception:
                result_json = None

            if isinstance(result_json, dict):
                # 1) 首选合并字段判断
                val = result_json.get("Scenario_match & Property_match")
                if isinstance(val, str) and val.strip().lower() == "yes":
                    need_rag = True
                else:
                    # 2) 退而求其次：两个字段都为 Yes 也触发
                    sm = result_json.get("scenario_match")
                    pm = result_json.get("property_match")
                    if (
                        isinstance(sm, str) and isinstance(pm, str)
                        and sm.strip().lower() == "yes"
                        or pm.strip().lower() == "yes"
                    ):
                        need_rag = True

            if not need_rag:
                # 兜底：宽松正则匹配（忽略大小写与引号/空格差异）
                pat = re.compile(r'"?Scenario_match\s*&\s*Property_match"?\s*:\s*"?yes"?', re.IGNORECASE)
                if pat.search(result):
                    need_rag = True
                else:
                    # 同时检查两个独立字段
                    pat2 = re.compile(r'"?scenario_match"?\s*:\s*"?yes"?', re.IGNORECASE)
                    pat3 = re.compile(r'"?property_match"?\s*:\s*"?yes"?', re.IGNORECASE)
                    if pat2.search(result) and pat3.search(result):
                        need_rag = True
        
        if need_rag:
            logger.info(f"对 {os.path.basename(fa)} vs {os.path.basename(fb)} 进行二次判断")
            
            # 使用 ReAct Agent 进行二次分析
            if self.use_react_agent:
                rag_result = await self.async_react_query(
                    fa, fb, cve_details, cwe, work_mode
                )
            else:
                # 进行RAG二次判断，传递二进制文件名和工作模式（旧方式，已弃用）
                rag_result = await self.async_rag_query2bot(
                    fa, fb, cve_details, cwe,
                    pre_binary_name=self.pre_binary_name,
                    post_binary_name=self.post_binary_name,
                    work_mode=work_mode
                )
            final_result = f"初次分析结果:\n{result}\n\nReAct智能分析结果:\n{rag_result}"
        else:
            final_result = result if result else "分析结果为空"
        
        # 缓存结果
        self._task_cache[cache_key] = final_result
        return final_result
    
    async def async_react_query(self, fa, fb, cve_details=None, cwe=None, work_mode: str = "reproduction") -> str:
        """使用 ReAct Agent 进行二次分析
        
        Args:
            fa: 补丁前的伪C文件路径
            fb: 补丁后的伪C文件路径
            cve_details: CVE详情
            cwe: CWE信息
            work_mode: 工作模式
        
        Returns:
            分析结果字符串
        """
        # 延迟导入，避免循环依赖
        from agent.vuln_react_agent import VulnReActRefiner
        
        # 懒初始化 ReAct Refiner
        if self._react_refiner is None:
            logger.info("初始化 ReAct Agent...")
            self._react_refiner = VulnReActRefiner(
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
            result = await self._react_refiner.refine(
                fa=fa,
                fb=fb,
                cve_details=cve_details or "",
                cwe=cwe or "",
                work_mode=work_mode
            )
            return result
        except Exception as e:
            logger.error(f"ReAct Agent 分析失败: {e}")
            # 降级到旧方式
            logger.info("降级到传统 RAG 分析...")
            return await self.async_rag_query2bot(
                fa, fb, cve_details, cwe,
                pre_binary_name=self.pre_binary_name,
                post_binary_name=self.post_binary_name,
                work_mode=work_mode
            )
    
    async def async_rag_query2bot(self, fa, fb, cve_details=None, cwe=None, pre_binary_name=None, post_binary_name=None, work_mode: str = "reproduction") -> str:
        """异步版本的rag_query2bot函数，获取函数调用链信息并添加到提示词中（旧方式，作为降级备选）
        
        Args:
            fa: 补丁前的伪C文件路径
            fb: 补丁后的伪C文件路径
            cve_details: CVE详情
            cwe: CWE信息
            pre_binary_name: 补丁前二进制文件名（如果提供则直接使用，不再推断）
            post_binary_name: 补丁后二进制文件名（如果提供则直接使用，不再推断）
            work_mode: 工作模式 - "reproduction"（漏洞复现）或 "discovery"（漏洞挖掘）
        """
        # 读两个.c文件的内容
        try:
            a_content = open(fa, 'r', encoding='utf-8').read()
            b_content = open(fb, 'r', encoding='utf-8').read()
        except Exception as e:
            logger.error(f"读取函数文件失败: {e}")
            return "读取函数文件失败"

        # 提取函数名
        pre_func_name = os.path.basename(fa).split('.')[0]
        post_func_name = os.path.basename(fb).split('.')[0]
        
        # 尝试获取二进制文件名
        try:
            # 如果外部已经传入了准确的二进制文件名，直接使用
            if pre_binary_name and post_binary_name:
                logger.info(f"使用传入的二进制文件名: pre={pre_binary_name}, post={post_binary_name}")
            else:
                # 否则从文件路径推断（旧逻辑，兼容没有传入参数的情况）
                # 约定结构：history/<chat_id>/bindiff/<binary_filename>/diff_xxx/folder_a|folder_b/<func>.c
                fa_dir = os.path.dirname(fa)
                fb_dir = os.path.dirname(fb)
    
                # 提取 chat_id 与 pre 二进制名
                # 结构：folder_a -> diff_xxx -> <binary_filename> -> bindiff -> <chat_id>
                binary_filename = os.path.basename(os.path.dirname(os.path.dirname(fa_dir)))
                chat_id = os.path.basename(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(fa_dir)))))
                history_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(fa_dir)))))
    
                # 使用 bindiff 目录名作为补丁前二进制名
                pre_binary_name = binary_filename
    
                # 根据“在文件名后缀之前插入 1”的规则生成补丁后二进制名
                # 规则示例：
                #  - libsal.so.0.0 -> libsal.so.01.0 （在最后一段 .数字 段之前对前一段数字追加 1）
                #  - setup.cgi      -> setup1.cgi   （在扩展名前插入 1）
                basename = os.path.basename(binary_filename)
                name_part, ext = os.path.splitext(basename)
    
                post_binary_name = f"{name_part}1{ext}"
    

                logger.info(f"从路径推断的二进制文件名: pre={pre_binary_name}, post={post_binary_name}")

            logger.info(f"尝试获取函数调用链信息: {pre_func_name} 和 {post_func_name} | pre_bin={pre_binary_name}, post_bin={post_binary_name}")
            logger.info(f"尝试获取函数调用链信息: {pre_func_name} 和 {post_func_name} | pre_bin={pre_binary_name}, post_bin={post_binary_name}")
            # 获取补丁前/后的函数调用链 JSON（包含 data_flow）
            pre_func_call_info = await self.get_function_call_info(pre_binary_name, pre_func_name)
            post_func_call_info = await self.get_function_call_info(post_binary_name, post_func_name)
            
            # 仅提取“关键参数的数据流”提供给大模型
            pre_func_context = format_vuln_context(pre_func_call_info)
            post_func_context = format_vuln_context(post_func_call_info)

            # 追加调用链代码切片
            try:
                pre_chain, pre_slices = self._collect_call_chain_slices(pre_func_call_info, "pre")
                post_chain, post_slices = self._collect_call_chain_slices(post_func_call_info, "post")

                pre_chain_text = self._format_call_chain_slices(pre_slices, "4️⃣ 调用链关键代码（补丁前）")
                post_chain_text = self._format_call_chain_slices(post_slices, "4️⃣ 调用链关键代码（补丁后）")

                if pre_chain_text:
                    pre_func_context = (pre_func_context + "\n\n" + pre_chain_text).strip()
                if post_chain_text:
                    post_func_context = (post_func_context + "\n\n" + post_chain_text).strip()
            except Exception as _err:
                logger.error(f"追加调用链代码切片失败: {_err}")

            # 控制台输出上下文，便于快速排查
            if pre_func_context:
                logger.debug("[RAG] 补丁前函数上下文:\n" + pre_func_context)
            else:
                logger.debug("[RAG] 补丁前函数上下文: <empty>")
            if post_func_context:
                logger.debug("[RAG] 补丁后函数上下文:\n" + post_func_context)
            else:
                logger.debug("[RAG] 补丁后函数上下文: <empty>")

            # 将函数上下文信息写入单独的 context_log，不污染 vuln_analysis_results.json
            try:
                with open(self.context_log, 'a', encoding='utf-8') as w:
                    w.write(f"=== Function Context: {os.path.basename(fa)} vs {os.path.basename(fb)} ===\n")
                    w.write("[Pre]\n")
                    w.write((pre_func_context or "<empty>") + "\n")
                    w.write("[Post]\n")
                    w.write((post_func_context or "<empty>") + "\n\n")
            except Exception as _e:
                logger.error(f"写入函数上下文到 context_log 失败: {_e}")
            
        except Exception as e:
            logger.error(f"获取函数调用链信息失败: {e}")
            pre_func_context = ""  # 如果获取失败，使用空字符串
            post_func_context = ""
        
        # 记录获取到的函数上下文信息
        logger.info("函数上下文信息获取完成")
        
        # 生成带有函数调用链信息的提示词
        prompt = self.make_rag_prompt(
            a_content,
            b_content,
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
                default_system_prompt="You are a security analysis assistant."
            )
        except Exception as e:
            logger.error(f"RAG推理失败: {e}")
            return f"RAG推理失败: {str(e)}"

        try:
            # 结果仍写入 vuln_analysis_results.json，但不包含上下文
            with open(self.log, 'a', encoding='utf-8') as w:
                w.write(f"=== {os.path.basename(fa)} vs {os.path.basename(fb)} (RAG二次判断) ===\n")
                w.write(result + "\n\n")
            logger.info(f"写入RAG分析结果到日志 {self.log}")

            # 上下文单独写入 context_log
            with open(self.context_log, 'a', encoding='utf-8') as wctx:
                wctx.write(f"=== {os.path.basename(fa)} vs {os.path.basename(fb)} (RAG上下文) ===\n")
                wctx.write("[Pre]\n")
                wctx.write((pre_func_context or "<empty>") + "\n")
                wctx.write("[Post]\n")
                wctx.write((post_func_context or "<empty>") + "\n\n")
        except Exception as e:
            logger.error(f"写RAG日志或上下文失败: {e}")

        return result if result else "RAG分析结果为空"

# 主函数
async def main(chat_id: str,
         history_root: str | Path,
         binary_filename: str,
         post_binary_filename: str = None,  # 新增参数：实际的补丁后文件名
         pre_c: str = None, post_c: str = None, cve_details: str = None, cwe: str = None, send_message=None,
         include_call_chain_code: bool = True,
         slice_before: int = DEFAULT_SLICE_BEFORE,
         slice_after: int = DEFAULT_SLICE_AFTER,
         danger_api_list: Optional[List[str]] = None,
         full_func_line_threshold: int = 300,
         work_mode: str = "reproduction",
         react_model_name: str = "DeepSeek",
         react_max_iterations: int = 20):
    """
    主函数：对比两个固件版本的二进制差异并分析漏洞
    
    Args:
        chat_id: 会话ID
        history_root: 历史记录根目录
        binary_filename: 二进制文件名
        post_binary_filename: 补丁后二进制文件名
        pre_c: 补丁前伪C文件路径
        post_c: 补丁后伪C文件路径
        cve_details: CVE详情（漏洞复现模式）或CWE描述（漏洞挖掘模式）
        cwe: CWE类型
        send_message: 消息发送回调
        include_call_chain_code: 是否包含调用链代码
        slice_before: 切片前行数
        slice_after: 切片后行数
        danger_api_list: 危险API列表
        full_func_line_threshold: 全函数行数阈值
        work_mode: 工作模式 - "reproduction"（漏洞复现）或 "discovery"（漏洞挖掘）
        react_model_name: ReAct Agent 使用的模型配置名称（对应 config.ini 中的 LLM.{model_name} 节）
    react_max_iterations: ReAct Agent 最大迭代次数
    """
    # ---------- 动态定位 ----------
    paths = locate_paths(chat_id, history_root, binary_filename)
    WORK_DIR     = Path(paths["WORK_DIR"])     
    OUTPUT_DIR   = Path(paths["OUTPUT_DIR"])
    RESULTS_FILE = paths["RESULTS_FILE"]
    FOLDER_A, FOLDER_B = paths["FOLDER_A"], paths["FOLDER_B"]
    LOG_FILE = paths["LOG_FILE"]

    globals().update(paths)        # 直接把常量名注入全局

    logger.info("路径确认：")
    for k, v in paths.items():
        logger.info(f"{k:<12}= {v}")
    logger.info("")


    logger.info(f"补丁前伪C路径: {pre_c}")
    logger.info(f"补丁后伪C路径: {post_c}")

    # 预构建伪C索引，供调用链切片使用
    pre_index = build_pseudo_index(pre_c) if pre_c else None
    post_index = build_pseudo_index(post_c) if post_c else None
    pseudo_indexes = {}
    if pre_index:
        pseudo_indexes["pre"] = pre_index
    if post_index:
        pseudo_indexes["post"] = post_index

    # 2. 从 BinDiff 结果中解析函数对应关系
    func_mapping = parse_result_funcs(RESULTS_FILE)
    logger.info(f"补丁变化函数对数量: {len(func_mapping)}")

    if not func_mapping:
        logger.warning("没有解析到变化的函数对，退出")
        await send_message("没有解析到变化的函数对",
                           "message",
                           agent="Detection Agent")
        return

    # 3. 拆分伪C文件，只提取需要分析的函数
    write_extracted(pre_c, func_mapping.keys(), FOLDER_A)    # 补丁前
    write_extracted(post_c, func_mapping.values(), FOLDER_B) # 补丁后

    # 4. 开始调用大模型进行差异分析
    # 传递实际的二进制文件名到 Refiner
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
        # ReAct Agent 配置
        use_react_agent=True,
        pre_pseudo_file=pre_c,
        post_pseudo_file=post_c,
        react_model_name=react_model_name,  # 使用函数参数
    react_max_iterations=react_max_iterations,
        send_message=send_message,
        history_dir=str(WORK_DIR),
    )

    # 定义并行处理函数对的任务列表
    tasks = []
    func_paths = []
    
    # 为每个函数对创建一个任务
    for pre_func, post_func in func_mapping.items():
        pre_func_path = os.path.join(FOLDER_A, f"{pre_func}.c")
        post_func_path = os.path.join(FOLDER_B, f"{post_func}.c")
        
        if os.path.exists(pre_func_path) and os.path.exists(post_func_path):
            tasks.append(r.async_query2bot(pre_func_path, post_func_path, cve_details, cwe, work_mode=work_mode))
            func_paths.append((pre_func_path, post_func_path))
        else:
            logger.warning(f"缺少文件 {pre_func_path} 或 {post_func_path}，跳过")
    
    # 使用信号量控制并发数量，防止同时创建过多任务
    concurrency_limit = 5  # 根据系统资源和API限制调整
    semaphore = asyncio.Semaphore(concurrency_limit)
    
    # 包装任务以使用信号量，并在完成后立即发送消息
    async def bounded_task_with_send(task, index, pre_path, post_path):
        async with semaphore:
            try:
                result = await task
                # 任务完成后立即发送消息给前端
                if send_message:
                    await send_message(
                        f"大模型分析 {os.path.basename(pre_path)} vs {os.path.basename(post_path)}结果：\n{result}",
                        "message",
                        agent=r.agent
                    )
                return index, result
            except Exception as e:
                logger.error(f"任务执行失败: {e}")
                error_msg = f"分析失败: {str(e)}"
                # 即使出现异常也发送错误消息
                if send_message:
                    await send_message(
                        f"大模型分析 {os.path.basename(pre_path)} vs {os.path.basename(post_path)}失败：\n{error_msg}",
                        "message",
                        agent=r.agent
                    )
                return index, error_msg
    
    # 创建受限制的任务列表，每个任务完成后会立即发送消息
    bounded_tasks = [
        bounded_task_with_send(task, i, func_paths[i][0], func_paths[i][1]) 
        for i, task in enumerate(tasks)
    ]
    
    # 使用 asyncio.gather 执行任务，但消息已在每个任务完成时发送
    # 结果按完成顺序发送给前端，用户可以实时看到进度
    await asyncio.gather(*bounded_tasks)
    # 5. 最后生成总结
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            results = f.read()
        
        # 使用token计数和智能截断来生成总结
        summary = await generate_smart_summary(results, r.agent, send_message)
        
        logger.info("总结报告：")
        logger.info(summary)
        if send_message:
            await send_message(
                f"漏洞分析总结：\n{summary}",
                "message",
                agent=r.agent
            )
    except Exception as e:
        logger.error(f"生成总结失败: {e}")
        if send_message:
            await send_message(
                f"未分析出差异结果",
                "message",
                agent=r.agent
            )
    logger.info("全部分析完成！")

# 包装函数，保持向后兼容性
async def llm_diff(chat_id: str, history_root: str, binary_filename: str, 
                 post_binary_filename: str = None,
                 pre_c: str = None, post_c: str = None, cve_details: str = None, 
                 cwe: str = None, send_message=None,
                 include_call_chain_code: bool = True,
                 slice_before: int = DEFAULT_SLICE_BEFORE,
                 slice_after: int = DEFAULT_SLICE_AFTER,
                 danger_api_list: Optional[List[str]] = None,
                 full_func_line_threshold: int = 300,
                 react_model_name: str = "DeepSeek",
                 react_max_iterations: int = 20):
    """包装函数，保持与原代码的兼容性"""
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
        react_model_name=react_model_name,
        react_max_iterations=react_max_iterations,
    )

if __name__ == "__main__":
    # 运行示例
    asyncio.run(main(
        chat_id="2025-11-25-9465-1",  
        history_root=r"/home/wzh/Desktop/Project/VulnAgent/history",
        binary_filename="rumpusd.exe",
        pre_c=r"/home/wzh/Desktop/Project/VulnAgent/history/2025-11-25-9465-1/ida/rumpusd.exe/rumpusd.exe_pseudo.c",
        post_c=r"/home/wzh/Desktop/Project/VulnAgent/history/2025-11-25-9465-1/ida/rumpusd10.exe1/rumpusd101.exe_pseudo.c",
        cve_details="CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        cwe="CWE-78",
    ))