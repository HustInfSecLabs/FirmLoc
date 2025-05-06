#!/usr/bin/env python3
import os
import re
import subprocess
from openai import OpenAI
from pathlib import Path
import glob, time
from IDAwork import export_and_extract
PROMPT = r"""
你是顶级的代码安全研究员。给你两个极其相似的 C/C++ 函数文件 [fileA] 与 [fileB]。
一般情况下，fileA = “旧版本”，fileB = “新版本(可能修复，也可能引入缺陷)”。
危险函数清单:下列函数一旦出现 / 被删除 / 被替换，极可能与溢出、命令注入、格式化字符串等漏洞相关：

[funcs]
    "printf","gets","scanf",
    "alloca","malloc","calloc","realloc",
    "memmove","memcpy","strcpy","strncpy","stpcpy","wcscpy","wcpcpy",
    "stpncpy","strlcpy","strscpy","wcsncpy","wcpncpy","wcslcpy",
    "strcat","strncat","strlcat","wcscat","wcslcat",
    "fopen","fread","fwrite","fclose","read",
    "system","send","recv",
    "sizeof","strlen","memset","wmemset","bcopy"
[funcs end]

**务必记住：**  
- “完全无漏洞并且差异不影响安全” 的情况极少；
- 只要差异涉及这些 [funcs]，请**务必**在结果的 `dangerous_calls` 字段中列出，并默认将其记为潜在漏洞（除非你能 100 % 证明安全）。  
- 如无法确定是否漏洞，请在 `vulnerabilities[].confidence` 标注 `"uncertain"`，也不要把 `no_vulnerability` 设为 true。 
- 如果无法 100 % 证明“无风险”，应当列入 `vulnerabilities` ，并将 `"confidence": "uncertain"`；  
- 绝不能因为缺少上下文就输出 `no_vulnerability: true` —— 那只有在 _代码完全相同且所有调用均安全_ 时才能给 true。

---

## 常见可疑差异提示（供你判断）  
1. **调用的函数被替换** → 可能是修补也可能是新漏洞  
2. **新增 / 删除边界检查** (`strlen`, `strcpy`→`strncpy`, `malloc`尺寸)  
3. **格式化字符串 / 日志** (`printf`, `sprintf`)  
4. **条件分支改动** (早期返回、权限判断)  
5. **资源释放 / 锁** (`free`, `close`, `mutex`)  

只要出现上述任何一种改动，都应输出一次 `vulnerabilities` 记录，并注明是否“修复”或“新增”。

---

## 输出必须是合法 JSON（不要有其它字符）

{
  "fileA": "<fileA 文件名>",
  "fileB": "<fileB 文件名>",
  "has_change": true,
  "changes": [
    {
      "lineA": 0,
      "lineB": 0,
      "codeA": "...",
      "codeB": "..."
    }
  ],
  "dangerous_calls": [                 // ★ 新增：出现的危险函数名列表
    "strcpy",
    "malloc"
  ],
  "vulnerabilities": [                 // 若无漏洞给 []
    {
      "type": "缓冲区溢出",
      "cause": "strcpy 未做边界检查",
      "location": "fileA",
      "lines": [23],
      "code_snippet": "strcpy(buf, src);",
      "confidence": "certain"
    }
  ],
  "statistics": {
    "<漏洞类型>": <数量>
  },
  "no_vulnerability": false                    // 只有在完全一致且能证明安全时才允许 true
}

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

# ———— 配置区 ————
def locate_paths(chat_id: str, history_root: str | Path) -> dict:
    history_root = Path(history_root).expanduser().resolve()
    """
    根据 chat_id 自动拼出相关目录 / 文件路径。
    返回 dict 用来替换原先的全局常量。
    """
    root     = history_root / chat_id
    ida_dir  = root / "ida"
    bd_dir   = root / "bindiff"

    print("DEBUG  bd_dir =", bd_dir)
    print("DEBUG  items  =", [p.name for p in bd_dir.iterdir()])
    matches = sorted(bd_dir.glob("*.results"))
    print("DEBUG  matches=", [m.name for m in matches])

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
    def __init__(self):
        self.log = LOG_FILE
        api_key = "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"
        if not api_key:
            raise RuntimeError("请先通过环境变量 OPENAI_API_KEY 设置你的 API Key")
        self.client = OpenAI(api_key=api_key)  # ✅ 手动传进去，最安全！

    def make_prompt(self, fa_content, fb_content):
        return PROMPT.replace("{$filea$}", fa_content).replace("{$fileb$}", fb_content)

    def query2bot(self, fa, fb):
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
            f"File: {os.path.basename(fb)}\n{b_content}"
        )

        try:
            resp = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": prompt}]
            )
            result = resp.choices[0].message.content
        except Exception as e:
            print(f"ChatGPT请求失败: {e}")
            return

        try:
            with open(self.log, 'a', encoding='utf-8') as w:
                w.write(f"=== {os.path.basename(fa)} vs {os.path.basename(fb)} ===\n")
                w.write(result + "\n\n")
            print(f"写入分析结果到日志 {self.log}")
        except Exception as e:
            print(f"写日志失败: {e}")



def main(chat_id: str,
    history_root: str | Path):
    # ---------- 动态定位 ----------
    paths = locate_paths(chat_id, history_root)
    WORK_DIR     = Path(paths["WORK_DIR"])     # 已是绝对
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
    c_files = export_and_extract(
        work_dir=WORK_DIR,                 # <— 替换
        output_dir=Path(OUTPUT_DIR)    # 存到同一个 diff 子目录
    )

    if len(c_files) < 2:
        print("伪C文件不足，退出")
        return

    pre_binary_name, pre_c_path = c_files[0]
    post_binary_name, post_c_path = c_files[1]

    print(f"\n补丁前伪C路径: {pre_c_path}")
    print(f"补丁后伪C路径: {post_c_path}")

    # 2. 从 BinDiff 结果中解析函数对应关系
    func_mapping = parse_result_funcs(RESULTS_FILE)
    print(f"补丁变化函数对数量: {len(func_mapping)}\n")

    if not func_mapping:
        print("没有解析到变化的函数对，退出")
        return

    # 3. 拆分伪C文件，只提取需要分析的函数
    write_extracted(pre_c_path, func_mapping.keys(), FOLDER_A)    # 补丁前
    write_extracted(post_c_path, func_mapping.values(), FOLDER_B) # 补丁后

    # 4. 开始调用大模型进行差异分析
    r = Refiner()

    for pre_func, post_func in func_mapping.items():
        pre_func_path = os.path.join(FOLDER_A, f"{pre_func}.c")
        post_func_path = os.path.join(FOLDER_B, f"{post_func}.c")

        #print(f"→ 准备分析 {os.path.basename(pre_func_path)} vs {os.path.basename(post_func_path)}")
        
        if os.path.exists(pre_func_path) and os.path.exists(post_func_path):
            r.query2bot(pre_func_path, post_func_path)
        else:
            print(f"缺少文件 {pre_func_path} 或 {post_func_path}，跳过")

    print("\n全部分析完成！")

if __name__ == "__main__":
    main("chat-bf5178a7", r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent\agent\history")