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

from model import AgentModel

# 读取漏洞类型对应的Scenario和Property的JSON文件路径
VULNERABILITY_SCENARIOS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'vulnerability_scenarios.json')

# 基础PROMPT模板
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

# 生成Scenario和Property的提示词
GENERATE_SCENARIO_PROMPT = """You are a security expert. Please generate a scenario and property for the given vulnerability type.

Vulnerability Type: {$vulnerability_type$}

A scenario should describe the conditions under which the vulnerability exists, in a format that can be answered with "Yes" or "No".
A property should describe the conditions under which a patch effectively fixes the vulnerability, also in a format that can be answered with "Yes" or "No".

Please provide your response in JSON format with the following structure:
{
  "scenario": "[Your scenario description]",
  "property": "[Your property description]"
}
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
    loop = asyncio.get_event_loop()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            result = await loop.run_in_executor(
                executor,
                lambda: gpt_inference(prompt=prompt, temperature=temperature, default_system_prompt=default_system_prompt)
            )
        # 确保返回的是字符串类型
        if isinstance(result, str):
            return result
        else:
            # 如果不是字符串，转换为字符串
            return str(result)
    except Exception as e:
        print(f"异步推理失败: {e}")
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
                print(f"警告: 历史记录格式不正确: {his}")
        messages.append({"role": "user", "content": prompt})
        result = llm_diff_agent.chat(prompt=prompt)

        return result
    except Exception as e:
        print(f"GPT推理失败: {e}")
        return f"GPT推理失败: {str(e)}"

# 加载漏洞类型对应的Scenario和Property
def load_vulnerability_scenarios():
    """加载漏洞类型对应的Scenario和Property"""
    if not os.path.exists(VULNERABILITY_SCENARIOS_FILE):
        return {}
    
    try:
        with open(VULNERABILITY_SCENARIOS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"加载漏洞场景文件失败: {e}")
        return {}

# 保存漏洞类型对应的Scenario和Property
def save_vulnerability_scenarios(scenarios):
    """保存漏洞类型对应的Scenario和Property"""
    try:
        with open(VULNERABILITY_SCENARIOS_FILE, 'w', encoding='utf-8') as f:
            json.dump(scenarios, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        print(f"保存漏洞场景文件失败: {e}")
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
        print(f"生成漏洞场景失败: {e}")
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
            print(f"无法找到cwe_samples.json文件，默认路径: {samples_path}")
            return {}
    
    try:
        with open(samples_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"加载cwe_samples.json失败: {e}")
        return {}

# 根据CWE类型选择正负样例
def select_cwe_samples(cwe_type, samples, num_positive=2, num_negative=2):
    """根据CWE类型选择指定数量的正负样例"""
    cwe_samples = samples.get(cwe_type, [])
    if not cwe_samples:
        print(f"未找到{cwe_type}类型的样例")
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

    print("DEBUG  bd_dir =")
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
  r'^[0-9A-F]{8}\s+[0-9A-F]{8}\s+'
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


def write_extracted(pseudo_file, base_names, out_dir):
    """
    仅拆分 base_names 中的函数，并以 base_name.c 保存。
    """
    os.makedirs(out_dir, exist_ok=True)
    funcs = split_functions(pseudo_file)
    lines = open(pseudo_file,'r',encoding='utf-8').read().splitlines(keepends=True)
    for base in base_names:
        if base not in funcs:
            print(f"未找到函数 “{base}”")
            continue
        i,j = funcs[base]
        out = os.path.join(out_dir, f"{base}.c")
        with open(out,'w',encoding='utf-8') as w:
            w.writelines(lines[i:j])
        print(f"  extracted {base} → {out}")

class Refiner:
    def __init__(self, LOG_FILE):
        self.log = LOG_FILE
        self.agent = "Detection Agent"
        self._task_cache = {}  # 初始化任务缓存字典

        #api_key = "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"
        #if not api_key:
        #    raise RuntimeError("请先通过环境变量 OPENAI_API_KEY 设置你的 API Key")
        #self.client = OpenAI(api_key=api_key) 

    def make_prompt(self, fa_content, fb_content, cve_details=None, cwe=None):
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
        
        # 使用基础模板生成最终prompt
        prompt = BASE_PROMPT.replace("{$vulnerability_type$}", vulnerability_type)
        prompt = prompt.replace("{$scenario$}", scenario)
        prompt = prompt.replace("{$property$}", property)
        prompt = prompt.replace("{$filea$}", fa_content)
        prompt = prompt.replace("{$fileb$}", fb_content)
        prompt = prompt.replace("{$cve_details$}", cve_details if cve_details else "")
        
        return prompt
        
    def make_rag_prompt(self, fa_content, fb_content, cve_details=None, cwe=None, pre_func_context=None, post_func_context=None):
        """生成带有RAG样例的提示词，包含函数调用链信息"""
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
            response = await loop.run_in_executor(
                None, 
                lambda: requests.post(url, data=data, timeout=60)  # 增加超时时间以适应IDA分析
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"API调用失败，状态码: {response.status_code}")
                print(f"响应内容: {response.text}")
                return {}
        except Exception as e:
            print(f"API调用异常: {e}")
            return {}
    
    def format_func_call_info(self, call_info):
        """格式化函数调用链信息为可读文本"""
        if not call_info:
            return ""
        
        formatted_info = []
        
        # 从新的响应格式中提取信息
        # 添加函数信息
        if "function_info" in call_info:
            func_info = call_info["function_info"]
            if isinstance(func_info, dict):
                # 如果function_info是字典，提取其中的信息
                if "name" in func_info:
                    formatted_info.append(f"函数名: {func_info['name']}")
                if "address" in func_info:
                    formatted_info.append(f"函数地址: {func_info['address']}")
                if "size" in func_info:
                    formatted_info.append(f"函数大小: {func_info['size']} 字节")
            else:
                # 否则直接显示
                formatted_info.append(f"函数信息: {func_info}")
        
        # 添加风险函数（sinks）
        if "sinks" in call_info and call_info["sinks"]:
            sinks = call_info["sinks"]
            if isinstance(sinks, list):
                formatted_info.append(f"风险函数: {', '.join(sinks)}")
            else:
                formatted_info.append(f"风险函数: {sinks}")
        
        # 添加调用者（callers）
        if "callers" in call_info and call_info["callers"]:
            callers = call_info["callers"]
            if isinstance(callers, list):
                formatted_info.append(f"调用该函数的函数: {', '.join(callers)}")
            else:
                formatted_info.append(f"调用该函数的函数: {callers}")
        
        # 添加函数调用链（chains）
        if "chains" in call_info and call_info["chains"]:
            chains = call_info["chains"]
            if isinstance(chains, list):
                # 格式化调用链，每个调用链占一行
                for i, chain in enumerate(chains, 1):
                    if isinstance(chain, list):
                        formatted_info.append(f"调用链 {i}: {' -> '.join(chain)}")
                    else:
                        formatted_info.append(f"调用链 {i}: {chain}")
            else:
                formatted_info.append(f"调用链: {chains}")
        
        # 添加评估结果（assessments）
        if "assessments" in call_info and call_info["assessments"]:
            assessments = call_info["assessments"]
            if isinstance(assessments, dict):
                for key, value in assessments.items():
                    formatted_info.append(f"{key}: {value}")
            else:
                formatted_info.append(f"评估结果: {assessments}")
        
        # # 兼容旧格式
        # if not formatted_info:  # 如果上面的新格式处理没有添加任何信息
        #     # 添加函数名（旧格式）
        #     if "function_name" in call_info:
        #         formatted_info.append(f"函数名: {call_info['function_name']}")
            
        #     # 添加被调用函数（旧格式）
        #     if "callees" in call_info and call_info["callees"]:
        #         formatted_info.append(f"被调用函数: {', '.join(call_info['callees'])}")
            
        #     # 添加函数调用链（旧格式）
        #     if "call_chain" in call_info and call_info["call_chain"]:
        #         formatted_info.append(f"函数调用链: {' -> '.join(call_info['call_chain'])}")
            
        #     # 添加函数特征（旧格式）
        #     if "features" in call_info and call_info["features"]:
        #         formatted_info.append(f"函数特征: {call_info['features']}")
        
        return "\n".join(formatted_info)
        
    async def async_query2bot(self, fa, fb, cve_details=None, cwe=None) -> str:
        """异步版本的query2bot函数"""
        print(f"→ 开始分析 {os.path.basename(fa)} vs {os.path.basename(fb)}")
        
        # 检查缓存中是否已有结果
        cache_key = (os.path.basename(fa), os.path.basename(fb))
        if cache_key in self._task_cache:
            print(f"← 从缓存获取 {os.path.basename(fa)} vs {os.path.basename(fb)} 的分析结果")
            return self._task_cache[cache_key]

        # 读两个.c文件的内容
        try:
            a_content = open(fa, 'r', encoding='utf-8').read()
            b_content = open(fb, 'r', encoding='utf-8').read()
        except Exception as e:
            print(f"读取函数文件失败: {e}")
            return f"读取函数文件失败: {str(e)}"

        prompt = self.make_prompt(
            f"File: {os.path.basename(fa)}\n{a_content}",
            f"File: {os.path.basename(fb)}\n{b_content}",
            cve_details=cve_details,
            cwe=cwe
        )

        try:
            result = await async_gpt_inference(
                prompt=prompt,
                temperature=0,
                default_system_prompt="You are a security analysis assistant."
            )
        except Exception as e:
            print(f"大模型推理失败: {e}")
            return f"大模型推理失败: {str(e)}"

        try:
            with open(self.log, 'a', encoding='utf-8') as w:
                w.write(f"=== {os.path.basename(fa)} vs {os.path.basename(fb)} ===\n")
                w.write(result + "\n\n")
            print(f"写入分析结果到日志 {self.log}")
        except Exception as e:
            print(f"写日志失败: {e}")
        
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
                        and pm.strip().lower() == "yes"
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
            print(f"→ 对 {os.path.basename(fa)} vs {os.path.basename(fb)} 进行二次判断")
            # 进行RAG二次判断
            rag_result = await self.async_rag_query2bot(fa, fb, cve_details, cwe)
            final_result = f"初次分析结果:\n{result}\n\nRAG二次分析结果:\n{rag_result}"
        else:
            final_result = result if result else "分析结果为空"
        
        # 缓存结果
        self._task_cache[cache_key] = final_result
        return final_result
    
    async def async_rag_query2bot(self, fa, fb, cve_details=None, cwe=None) -> str:
        """异步版本的rag_query2bot函数，获取函数调用链信息并添加到提示词中"""
        # 读两个.c文件的内容
        try:
            a_content = open(fa, 'r', encoding='utf-8').read()
            b_content = open(fb, 'r', encoding='utf-8').read()
        except Exception as e:
            print(f"读取函数文件失败: {e}")
            return "读取函数文件失败"

        # 提取函数名
        pre_func_name = os.path.basename(fa).split('.')[0]
        post_func_name = os.path.basename(fb).split('.')[0]
        
        # 尝试从文件路径推断二进制文件名（不依赖 locate_paths，不使用 dummy）
        try:
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

            print(f"尝试获取函数调用链信息: {pre_func_name} 和 {post_func_name} | chat_id={chat_id}, pre_bin={pre_binary_name}, post_bin={post_binary_name}")

            # 获取补丁前函数调用链
            pre_func_call_info = await self.get_function_call_info(pre_binary_name, pre_func_name)

            # 获取补丁后函数调用链（按规则生成的唯一 post 名称）
            post_func_call_info = await self.get_function_call_info(post_binary_name, post_func_name)
            
            # 格式化函数调用链信息
            pre_func_context = self.format_func_call_info(pre_func_call_info)
            post_func_context = self.format_func_call_info(post_func_call_info)

            # 控制台输出上下文，便于快速排查
            if pre_func_context:
                print("[RAG] 补丁前函数上下文:\n" + pre_func_context)
            else:
                print("[RAG] 补丁前函数上下文: <empty>")
            if post_func_context:
                print("[RAG] 补丁后函数上下文:\n" + post_func_context)
            else:
                print("[RAG] 补丁后函数上下文: <empty>")

            # 将函数上下文信息记录到日志文件
            try:
                with open(self.log, 'a', encoding='utf-8') as w:
                    w.write(f"=== Function Context: {os.path.basename(fa)} vs {os.path.basename(fb)} ===\n")
                    w.write("[Pre]\n")
                    w.write((pre_func_context or "<empty>") + "\n")
                    w.write("[Post]\n")
                    w.write((post_func_context or "<empty>") + "\n\n")
            except Exception as _e:
                print(f"写入函数上下文到日志失败: {_e}")
            
        except Exception as e:
            print(f"获取函数调用链信息失败: {e}")
            pre_func_context = ""  # 如果获取失败，使用空字符串
            post_func_context = ""
        
        # 记录获取到的函数上下文信息
        print(f"函数上下文信息获取完成")
        
        # 生成带有函数调用链信息的提示词
        prompt = self.make_rag_prompt(
            a_content,
            b_content,
            cve_details=cve_details,
            cwe=cwe,
            pre_func_context=pre_func_context,
            post_func_context=post_func_context
        )

        try:
            result = await async_gpt_inference(
                prompt=prompt,
                temperature=0,
                default_system_prompt="You are a security analysis assistant."
            )
        except Exception as e:
            print(f"GPT RAG推理失败: {e}")
            return f"GPT RAG推理失败: {str(e)}"

        try:
            with open(self.log, 'a', encoding='utf-8') as w:
                w.write(f"=== {os.path.basename(fa)} vs {os.path.basename(fb)} (RAG二次判断) ===\n")
                # 在结果前记录一次上下文，便于日志阅读
                w.write("[Pre]\n")
                w.write((pre_func_context or "<empty>") + "\n")
                w.write("[Post]\n")
                w.write((post_func_context or "<empty>") + "\n")
                w.write(result + "\n\n")
            print(f"写入RAG分析结果到日志 {self.log}")
        except Exception as e:
            print(f"写RAG日志失败: {e}")

        # 在返回的输出中追加上下文，便于前端/调用方查看（不干扰模型输出的 JSON 本体，先给 JSON 再给上下文）
        if result:
            appended = (
                result
                + "\n\n[RAG 函数上下文]\n[Pre]\n" + (pre_func_context or "<empty>")
                + "\n[Post]\n" + (post_func_context or "<empty>")
            )
            return appended
        return "RAG分析结果为空"

# 主函数
async def main(chat_id: str,
         history_root: str | Path,
         binary_filename: str,
         pre_c: str = None, post_c: str = None, cve_details: str = None, cwe: str = None, send_message=None):
    # ---------- 动态定位 ----------
    paths = locate_paths(chat_id, history_root, binary_filename)
    WORK_DIR     = Path(paths["WORK_DIR"])     
    OUTPUT_DIR   = Path(paths["OUTPUT_DIR"])
    RESULTS_FILE = paths["RESULTS_FILE"]
    FOLDER_A, FOLDER_B = paths["FOLDER_A"], paths["FOLDER_B"]
    LOG_FILE = paths["LOG_FILE"]

    globals().update(paths)        # 直接把常量名注入全局

    print("路径确认：")
    for k, v in paths.items():
        print(f"{k:<12}= {v}")
    print()


    print(f"\n补丁前伪C路径: {pre_c}")
    print(f"补丁后伪C路径: {post_c}")

    # 2. 从 BinDiff 结果中解析函数对应关系
    func_mapping = parse_result_funcs(RESULTS_FILE)
    print(f"补丁变化函数对数量: {len(func_mapping)}\n")

    if not func_mapping:
        print("没有解析到变化的函数对，退出")
        await send_message("没有解析到变化的函数对",
                           "message",
                           agent="Detection Agent")
        return

    # 3. 拆分伪C文件，只提取需要分析的函数
    write_extracted(pre_c, func_mapping.keys(), FOLDER_A)    # 补丁前
    write_extracted(post_c, func_mapping.values(), FOLDER_B) # 补丁后

    # 4. 开始调用大模型进行差异分析
    r = Refiner(LOG_FILE)

    # 定义并行处理函数对的任务列表
    tasks = []
    func_paths = []
    
    # 为每个函数对创建一个任务
    for pre_func, post_func in func_mapping.items():
        pre_func_path = os.path.join(FOLDER_A, f"{pre_func}.c")
        post_func_path = os.path.join(FOLDER_B, f"{post_func}.c")
        
        if os.path.exists(pre_func_path) and os.path.exists(post_func_path):
            tasks.append(r.async_query2bot(pre_func_path, post_func_path, cve_details, cwe))
            func_paths.append((pre_func_path, post_func_path))
        else:
            print(f"缺少文件 {pre_func_path} 或 {post_func_path}，跳过")
    
    # 使用信号量控制并发数量，防止同时创建过多任务
    concurrency_limit = 5  # 根据系统资源和API限制调整
    semaphore = asyncio.Semaphore(concurrency_limit)
    
    # 包装任务以使用信号量
    async def bounded_task(task, index):
        async with semaphore:
            try:
                result = await task
                # 确保返回正确格式的元组
                return index, result
            except Exception as e:
                print(f"任务执行失败: {e}")
                # 即使出现异常，也确保返回正确格式的元组
                return index, f"分析失败: {str(e)}"
    
    # 创建受限制的任务列表
    bounded_tasks = [bounded_task(task, i) for i, task in enumerate(tasks)]
    
    # 并行执行所有任务
    results = await asyncio.gather(*bounded_tasks)
    
    # 按照原始顺序处理结果
    ordered_results = sorted(results, key=lambda x: x[0])
    
    # 发送结果到客户端
    for i, (_, result) in enumerate(ordered_results):
        pre_func_path, post_func_path = func_paths[i]
        if send_message:
            await send_message(
                f"大模型分析 {os.path.basename(pre_func_path)} vs {os.path.basename(post_func_path)}结果：\n{result}",
                "message",
                agent = r.agent
            )
    # 5. 最后生成总结
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            results = f.read()
        summary_prompt = SUMMARY_PROMPT.replace("{$result$}", results)
        summary = await async_gpt_inference(
            prompt=summary_prompt,
            temperature=0,
            default_system_prompt="You are a security analysis summary assistant."
        )
        print("\n总结报告：")
        print(summary)
        if send_message:
            await send_message(
                f"漏洞分析总结：\n{summary}",
                "message",
                agent=r.agent
            )
    except Exception as e:
        print(f"生成总结失败: {e}")
        if send_message:
            await send_message(
                f"未分析出差异结果",
                "message",
                agent=r.agent
            )
    print("\n全部分析完成！")

# 包装函数，保持向后兼容性
async def llm_diff(chat_id: str, history_root: str, binary_filename: str, 
                 pre_c: str = None, post_c: str = None, cve_details: str = None, 
                 cwe: str = None, send_message=None):
    """包装函数，保持与原代码的兼容性"""
    return await main(chat_id, history_root, binary_filename, pre_c, post_c, 
                     cve_details, cwe, send_message)

if __name__ == "__main__":
    # 运行示例
    asyncio.run(main(
        chat_id="2025-09-26-660-1",  
        history_root=r"/home/wzh/Desktop/Project/VulnAgent/history",
        binary_filename="libsal.so.0.0",
        pre_c=r"/home/wzh/Desktop/Project/VulnAgent/history/2025-09-26-660-1/ida/libsal.so.0.0/libsal.so.0.0_pseudo.c",
        post_c=r"/home/wzh/Desktop/Project/VulnAgent/history/2025-09-26-660-1/ida/libsal.so.0.01/libsal.so.01.0_pseudo.c",
        cve_details="Certain NETGEAR devices are affected by command injection by an unauthenticated attacker via the vulnerable /sqfs/lib/libsal.so.0.0 library used by a CGI application, as demonstrated by setup.cgi?token=';$HTTP_USER_AGENT;' with an OS command in the User-Agent field. This affects GC108P before 1.0.7.3, GC108PP before 1.0.7.3, GS108Tv3 before 7.0.6.3, GS110TPPv1 before 7.0.6.3, GS110TPv3 before 7.0.6.3, GS110TUPv1 before 1.0.4.3, GS710TUPv1 before 1.0.4.3, GS716TP before 1.0.2.3, GS716TPP before 1.0.2.3, GS724TPPv1 before 2.0.4.3, GS724TPv2 before 2.0.4.3, GS728TPPv2 before 6.0.6.3, GS728TPv2 before 6.0.6.3, GS752TPPv1 before 6.0.6.3, GS752TPv2 before 6.0.6.3, MS510TXM before 1.0.2.3, and MS510TXUP before 1.0.2.3.",
        cwe="CWE-78",
    ))