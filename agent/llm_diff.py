#!/usr/bin/env python3
import os
import re
import json
import subprocess
import tiktoken
from openai import OpenAI
from pathlib import Path
import glob, time
# from IDAwork import export_and_extract

# 读取漏洞类型对应的Scenario和Property的JSON文件路径
VULNERABILITY_SCENARIOS_FILE = os.path.join(os.path.dirname(__file__), 'vulnerability_scenarios.json')

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
# GPT 调用
COST_TOKEN = 0
TPM = 4000000
MODEL = "deepseek-chat"  # 可换成 "gpt-4o-mini" / "deepseek-reasoner" 等

# 根据 MODEL 自动设置 API key／base_url
if MODEL == "gpt-4o-mini":
    os.environ["OPENAI_API_KEY"] = "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"
    MAX_WINDOWS_LENGTH = 120 * 1024
if MODEL == "o3-mini-2025-01-31":
    os.environ["OPENAI_API_KEY"] = "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"
    MAX_WINDOWS_LENGTH = 120 * 1024
if MODEL == "gpt-4o":
    os.environ["OPENAI_API_KEY"] = "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"
    MAX_WINDOWS_LENGTH = 120 * 1024
elif MODEL == "deepseek-reasoner":
    os.environ["OPENAI_API_KEY"] = "sk-586b5dbc658847f4a555ea5fd804be5a"
    os.environ["OPENAI_BASE_URL"] = "https://api.deepseek.com/v1"
elif MODEL == "glm-4.5":
    os.environ["OPENAI_API_KEY"] = "b5ab63e977d24624b25c723cdedd596b.hKH1poPGWBQlg2Bn"
    os.environ["OPENAI_BASE_URL"] = "https://open.bigmodel.cn/api/paas/v4"
elif MODEL == "deepseek-chat":
    os.environ["OPENAI_API_KEY"] = "sk-edc3857234ed4d72a9c497252bcc8d86"
    os.environ["OPENAI_BASE_URL"] = "https://api.deepseek.com/v1"

gpt_encoder = tiktoken.get_encoding("o200k_base")

def gpt_inference(prompt: str = None, temperature: int = 0, default_system_prompt: str = None, history: list = []):
    global COST_TOKEN
    client = OpenAI()
    system_prompt = "You are a helpful security assistant." if default_system_prompt == None else default_system_prompt
    messages = [{"role": "system", "content": system_prompt}]
    for his in history:
        q, a = his
        messages.append({"role": "user", "content": q})
        messages.append({"role": "assistant", "content": a})
    messages.append({"role": "user", "content": prompt})

    # rate limit
    prompt_length = len(gpt_encoder.encode(prompt))
    # if MODEL in ["gpt-4o-mini", "o3-mini-2025-01-31", "gpt-4o"]:
    #     if COST_TOKEN + prompt_length > TPM:
    #         time.sleep(70)
    #         COST_TOKEN = 0

    if MODEL == "o3-mini-2025-01-31":
        completion = client.chat.completions.create(model=MODEL, messages=messages)
    else:
        completion = client.chat.completions.create(model=MODEL, temperature=temperature, messages=messages)
    COST_TOKEN += completion.usage.total_tokens

    # rate limit
    if MODEL == "deepseek_reasoner":
        time.sleep(5)

    return completion.choices[0].message.content

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

    def query2bot(self, fa, fb, cve_details=None, cwe=None) -> str:
        print(f"→ 开始分析 {os.path.basename(fa)} vs {os.path.basename(fb)}")

        # 读两个.c文件的内容
        try:
            a_content = open(fa, 'r', encoding='utf-8').read()
            b_content = open(fb, 'r', encoding='utf-8').read()
        except Exception as e:
            print(f"读取函数文件失败: {e}")
            return

        prompt = self.make_prompt(
            f"File: {os.path.basename(fa)}\n{a_content}",
            f"File: {os.path.basename(fb)}\n{b_content}",
            cve_details=cve_details,
            cwe=cwe
        )

        try:
            result = gpt_inference(
                prompt=prompt,
                temperature=0,
                default_system_prompt="You are a security analysis assistant."
            )
        except Exception as e:
            print(f"GPT 推理失败: {e}")
            return

        try:
            with open(self.log, 'a', encoding='utf-8') as w:
                w.write(f"=== {os.path.basename(fa)} vs {os.path.basename(fb)} ===\n")
                w.write(result + "\n\n")
            print(f"写入分析结果到日志 {self.log}")
        except Exception as e:
            print(f"写日志失败: {e}")

        return result if result else None



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

    # 1. 调用导出伪C函数
    # c_files = export_and_extract(
    #     work_dir=WORK_DIR,                 # <— 替换
    #     output_dir=Path(OUTPUT_DIR)    # 存到同一个 diff 子目录
    # )

    # if len(c_files) < 2:
    #     print("伪C文件不足，退出")
    #     return

    # pre_binary_name, pre_c_path = c_files[0]
    # post_binary_name, post_c_path = c_files[1]
    # pre_c = "/home/wzh/Desktop/Project/VulnAgent/history/20250514/ida/boxlogin/boxlogin_pseudo.c"
    # post_c = "/home/wzh/Desktop/Project/VulnAgent/history/20250514/ida/boxlogin1/boxlogin_pseudo.c"
    # pre_c_path = /home/wzh/Desktop/Project/VulnAgent/history/20250514/ida/boxlogin"
    # post_c_path = "/home/wzh/Desktop/Project/VulnAgent/history/20250514/ida/boxlogin1"
    #pre_c_path = os.path.dirname(pre_c)
    #post_c_path = os.path.dirname(post_c)

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

    for pre_func, post_func in func_mapping.items():
        pre_func_path = os.path.join(FOLDER_A, f"{pre_func}.c")
        post_func_path = os.path.join(FOLDER_B, f"{post_func}.c")

        #print(f"→ 准备分析 {os.path.basename(pre_func_path)} vs {os.path.basename(post_func_path)}")
        
        if os.path.exists(pre_func_path) and os.path.exists(post_func_path):
        # if os.path.basename(pre_func_path) == "sub_42DCCC.c":
            result = r.query2bot(pre_func_path, post_func_path, cve_details, cwe)
            if send_message:
                await send_message(
                    f"大模型分析 {os.path.basename(pre_func_path)} vs {os.path.basename(post_func_path)}结果：\n{result}",
                    "message",
                    agent = r.agent
                )
        else:
            print(f"缺少文件 {pre_func_path} 或 {post_func_path}，跳过")
    # 5. 最后生成总结
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            results = f.read()
        summary_prompt = SUMMARY_PROMPT.replace("{$result$}", results)
        summary = gpt_inference(
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

if __name__ == "__main__":
    main(
        chat_id="chat-CVE-2019-20760",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent\agent\history",
        binary_filename="proccgi",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent\agent\history\chat-CVE-2019-20760\ida\proccgi\proccgi26.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent\agent\history\chat-CVE-2019-20760\ida\proccgi\proccgi26.c"
    )