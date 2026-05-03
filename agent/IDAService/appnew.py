from flask import Flask, request, send_file, abort, jsonify
import tempfile
import os, sys, zipfile
import subprocess
import shutil
import logging
from datetime import datetime
import pyautogui
import time
import psutil, json
import pygetwindow as gw
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Flask服务端口
port = 5000

# 配置 PYTHONHOME 和 PYTHONPATH 环境变量
PYTHONHOME = r"D:\Software\Anaconda3"
PYTHONPATH = r"D:\Software\Anaconda3\Lib;D:\Software\Anaconda3\DLLs"

# 配置ida、idat路径

IDA32_PATH = r"D:\IDA9.0\IDA\ida.exe" # ida32安装路径
IDA64_PATH = r"D:\IDA9.0\IDA\ida.exe" # ida64安装路径
IDAT32_PATH = r"D:\IDA9.0\IDA\idat.exe"
IDAT64_PATH = r"D:\IDA9.0\IDA\idat.exe"
# 配置分析脚本路径, 确保绝对路径
BINEXPORT_SCRIPT = os.path.abspath("export_binexport.py")
BINEXPORT_FAST_SCRIPT = os.path.abspath("export_binexport_fast.py")
EXPORT_SCRIPT = os.path.abspath("export_hexrays.py")
EXPORT_STRINGS_SCRIPT = os.path.abspath("export_strings.py")
ANALYZE_SCRIPT = os.path.abspath("analyze.py")
WAIT_SCRIPT = os.path.abspath("wait_for_analysis.py")
STRING_XREF_SCRIPT = os.path.abspath("string_xref_analysis.py")

# 最大文件大小限制
MAX_FILE_SIZE = 1024 * 1024 * 1024 * 5  # 5GB
TIMEOUT = 3000  # 50分钟超时

# 导出伪C代码的等待检测时间
max_wait_time = 30  # 最大等待时间（秒）
check_interval = 0.5  # 检查间隔（秒）

# BinDiff CLI (optional; used by batch diff endpoint)
BINDIFF_CLI = os.environ.get("BINDIFF_CLI", r"d:\\Bindiff8\\bin\\bindiff.exe")

def clear_ida_cache(bin_path):
    """
    删除与bin_path相关的IDA缓存文件（如 .id0/.id1/.idb/.nam/.til 等）
    支持扩展名为.so、.bin等的 ELF 文件。
    """
    patterns = [
        bin_path + '.id0',
        bin_path + '.id1',
        bin_path + '.id2',
        bin_path + '.nam',
        bin_path + '.til',
        bin_path + '.idb',
        bin_path + '.i64',

    ]
    for file_path in patterns:
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.info(f"[Cache Clean] Removed: {file_path}")
        except Exception as e:
            logger.warning(f"[Cache Clean] Failed to remove {file_path}: {str(e)}")

def wait_for_ida_window(title_keyword="IDA", timeout=60):
    """等待 IDA 窗口出现在前台"""
    elapsed = 0
    while elapsed < timeout:
        windows = gw.getWindowsWithTitle(title_keyword)
        for w in windows:
            if title_keyword.lower() in w.title.lower():
                try:
                    w.activate()
                    w.maximize()
                    logger.info(f"IDA window activated: {w.title}")
                    return True
                except Exception as e:
                    logger.warning(f"Failed to activate window: {e}")
        time.sleep(1)
        elapsed += 1
    logger.warning("Timeout waiting for IDA window to appear.")
    return False



# 配置日志记录
def setup_logger():
    # 创建log目录
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "log")
    os.makedirs(log_dir, exist_ok=True)
    
    # 设置日志文件名
    log_file = os.path.join(log_dir, f"{datetime.now().strftime('%Y%m%d')}.log")
    
    # 配置日志格式和级别
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    return logging.getLogger(__name__)

# 初始化logger
logger = setup_logger()

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

logger.info(f"Analyze script path: {BINEXPORT_SCRIPT}")
logger.info(f"Export script path: {EXPORT_SCRIPT}")
logger.info(f"Analyze script path: {ANALYZE_SCRIPT}")

# 创建base输出目录：ida_output\{日期}
base_dir = os.path.dirname(os.path.abspath(__file__))
ida_output_dir = os.path.join(base_dir, "ida_output")
os.makedirs(ida_output_dir, exist_ok=True)


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def list_old_new_pairs(
    old_dir: str,
    new_dir: str,
    old_prefix: str = "old_",
    new_prefix: str = "new_",
) -> List[Tuple[str, str, str]]:
    """
    Scan two directories for old/new binaries and pair them by stripping prefixes.

    Example:
      old_ash -> key=ash
      new_ash -> key=ash

    Returns: [(pair_key, old_path, new_path), ...]
    """
    old_map: Dict[str, str] = {}
    new_map: Dict[str, str] = {}

    for p in Path(old_dir).iterdir():
        if p.is_file() and p.name.startswith(old_prefix):
            key = p.name[len(old_prefix) :]
            old_map[key] = str(p)

    for p in Path(new_dir).iterdir():
        if p.is_file() and p.name.startswith(new_prefix):
            key = p.name[len(new_prefix) :]
            new_map[key] = str(p)

    keys = sorted(set(old_map.keys()) & set(new_map.keys()))
    return [(k, old_map[k], new_map[k]) for k in keys]


def _select_idat_path(ida_version: str) -> str:
    ida_version = (ida_version or "ida").lower()
    return IDAT64_PATH if ida_version == "ida64" else IDAT32_PATH


def _prepare_working_binary(
    input_file_path: str,
    work_dir: str,
    copy_to_work_dir: bool = True,
) -> str:
    src = os.path.abspath(input_file_path)
    if not os.path.exists(src) or not os.path.isfile(src):
        raise FileNotFoundError(f"Binary not found: {src}")

    ensure_dir(work_dir)

    if not copy_to_work_dir:
        return src

    dst = os.path.join(work_dir, os.path.basename(src))
    dst_meta = dst + ".src.json"
    try:
        # Avoid redundant copies when rerunning, but make sure it's the SAME source file.
        # Using size-only can cause incorrect reuse across tasks with shared output_dir.
        if os.path.exists(dst) and os.path.getsize(dst) == os.path.getsize(src):
            if os.path.exists(dst_meta):
                try:
                    with open(dst_meta, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                    if os.path.abspath(meta.get("src_path", "")) == src:
                        return dst
                except Exception:
                    pass
    except Exception:
        pass

    shutil.copy2(src, dst)
    try:
        with open(dst_meta, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "src_path": src,
                    "dst_path": os.path.abspath(dst),
                    "copied_at": datetime.now().isoformat(timespec="seconds"),
                    "src_size": os.path.getsize(src),
                },
                f,
                ensure_ascii=False,
                indent=2,
            )
    except Exception:
        logger.exception(f"Failed to write binary copy meta: {dst_meta}")
    return dst


def _run_ida_binexport(
    bin_path: str,
    work_dir: str,
    ida_version: str = "ida",
    timeout_sec: int = 3600,
    extra_path_dirs: Optional[List[str]] = None,
    wait_analysis: bool = True,
    reuse_existing: bool = True,
    force_reexport: bool = False,
) -> Tuple[str, Optional[str]]:
    """
    Run IDA(idat) + BinExport plugin script and return (binexport_path, idb_path?).
    """
    idat_path = _select_idat_path(ida_version)

    expected = os.path.join(work_dir, Path(bin_path).name + ".BinExport")
    meta_path = expected + ".meta.json"

    def _meta_matches() -> bool:
        try:
            if not os.path.exists(meta_path):
                return False
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            return bool(meta.get("wait_analysis")) == bool(wait_analysis) and str(meta.get("ida_version")) == str(ida_version)
        except Exception:
            return False

    # Fast path: reuse existing BinExport if present and metadata matches.
    if reuse_existing and not force_reexport:
        try:
            if os.path.exists(expected) and os.path.getsize(expected) > 0 and _meta_matches():
                return expected, None
        except Exception:
            pass

    if force_reexport:
        try:
            if os.path.exists(expected):
                os.remove(expected)
        except Exception:
            pass
        try:
            if os.path.exists(meta_path):
                os.remove(meta_path)
        except Exception:
            pass

    cmd = [
        idat_path,
        "-A",
        "-T",
        f'-S"{BINEXPORT_SCRIPT if wait_analysis else BINEXPORT_FAST_SCRIPT}"',
        bin_path,
    ]
    logger.info(f"Executing: {' '.join(cmd)}")

    proc_env = os.environ.copy()
    # Avoid Conda/virtualenv variables breaking IDA's embedded Python runtime.
    for k in ["PYTHONHOME", "PYTHONPATH", "PYTHONNOUSERSITE"]:
        if k in proc_env:
            proc_env.pop(k, None)

    # Ensure IDA install + plugins directories are on PATH so dependent DLLs can be resolved.
    # Many BinDiff/BinExport plugin builds ship extra DLLs that must be discoverable by the loader.
    ida_dir = os.path.dirname(idat_path)
    path_prefixes: List[str] = []
    if ida_dir:
        path_prefixes.append(ida_dir)
        ida_plugins_dir = os.path.join(ida_dir, "plugins")
        if os.path.isdir(ida_plugins_dir):
            path_prefixes.append(ida_plugins_dir)

    if extra_path_dirs:
        for d in extra_path_dirs:
            if d and os.path.isdir(d):
                path_prefixes.append(d)

    if path_prefixes:
        proc_env["PATH"] = os.pathsep.join(path_prefixes) + os.pathsep + proc_env.get("PATH", "")

    # Optional override: if you really want to force an external Python runtime for IDAPython,
    # set these environment variables before starting the service.
    ida_pythonhome = os.environ.get("IDA_PYTHONHOME", "").strip()
    ida_pythonpath = os.environ.get("IDA_PYTHONPATH", "").strip()
    if ida_pythonhome:
        proc_env["PYTHONHOME"] = ida_pythonhome
    if ida_pythonpath:
        proc_env["PYTHONPATH"] = ida_pythonpath

    result = subprocess.run(
        cmd,
        cwd=work_dir,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        timeout=timeout_sec,
        env=proc_env,
    )

    if result.stdout:
        logger.info(f"IDA stdout: {result.stdout.strip()}")
    if result.stderr:
        logger.info(f"IDA stderr: {result.stderr.strip()}")

    if result.returncode != 0:
        raise RuntimeError(
            "IDA subprocess failed.\n"
            f"cmd={cmd}\n"
            f"returncode={result.returncode}\n"
            f"stdout={result.stdout}\n"
            f"stderr={result.stderr}"
        )

    expected_export = bin_path + ".BinExport"
    export_path = expected_export if os.path.exists(expected_export) else None
    if not export_path:
        # Fallback: find by filename in work_dir
        target_name = (Path(bin_path).name + ".BinExport").lower()
        for p in Path(work_dir).iterdir():
            if p.is_file() and p.name.lower() == target_name:
                export_path = str(p)
                break

    if not export_path or not os.path.exists(export_path) or os.path.getsize(export_path) == 0:
        raise RuntimeError(f"BinExport file missing or empty: {export_path or expected_export}")

    # Persist a small metadata file so we can safely reuse exports across runs.
    try:
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "generated_at": datetime.now().isoformat(timespec="seconds"),
                    "bin_path": os.path.abspath(bin_path),
                    "work_dir": os.path.abspath(work_dir),
                    "ida_version": ida_version,
                    "idat_path": idat_path,
                    "wait_analysis": bool(wait_analysis),
                },
                f,
                ensure_ascii=False,
                indent=2,
            )
    except Exception:
        logger.exception(f"Failed to write binexport meta file: {meta_path}")

    idb_path: Optional[str] = None
    for cand in [bin_path + ".i64", bin_path + ".idb"]:
        if os.path.exists(cand) and os.path.getsize(cand) > 0:
            idb_path = cand
            break

    return export_path, idb_path


def _run_bindiff_cli(
    primary_binexport: str,
    secondary_binexport: str,
    out_dir: str,
    bindiff_cli: Optional[str] = None,
    timeout_sec: int = 3600,
    output_format: str = "sqlite",
) -> str:
    """
    Run BinDiff CLI and return the latest produced *.results path.
    """
    ensure_dir(out_dir)
    cli = bindiff_cli or BINDIFF_CLI

    def _is_sqlite_db(p: str) -> bool:
        try:
            with open(p, "rb") as f:
                head = f.read(16)
            return head.startswith(b"SQLite format 3")
        except Exception:
            return False

    fmt = (output_format or "").strip().lower()
    cmd = [cli, primary_binexport, secondary_binexport, "--output_dir", out_dir]
    if fmt:
        cmd.extend(["--output_format", fmt])

    logger.info(f"[BinDiff CMD] {' '.join(cmd)}")
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout_sec)

    if r.returncode != 0:
        # Fallback: some BinDiff versions default to sqlite when output_format is omitted.
        if fmt:
            cmd2 = [cli, primary_binexport, secondary_binexport, "--output_dir", out_dir]
            logger.info(f"[BinDiff Retry CMD] {' '.join(cmd2)}")
            r2 = subprocess.run(cmd2, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout_sec)
            if r2.returncode != 0:
                raise RuntimeError(f"BinDiff failed.\ncmd={cmd2}\nstdout={r2.stdout}\nstderr={r2.stderr}")
        else:
            raise RuntimeError(f"BinDiff failed.\ncmd={cmd}\nstdout={r.stdout}\nstderr={r.stderr}")

    # Collect candidates and prefer sqlite DB results.
    candidates = [os.path.join(out_dir, f) for f in os.listdir(out_dir) if os.path.isfile(os.path.join(out_dir, f))]
    candidates.sort(key=os.path.getmtime, reverse=True)

    results_files = [p for p in candidates if p.lower().endswith(".results")]
    if not results_files:
        raise RuntimeError(f"BinDiff finished but produced no .results file in: {out_dir}. Files={candidates}")

    # If caller requested log (text) output, return the newest .results as-is.
    if fmt in {"log", "text"}:
        return results_files[0]

    # Otherwise, prefer sqlite DB results (for similarity queries).
    sqlite_candidates = [p for p in results_files if _is_sqlite_db(p)]
    if sqlite_candidates:
        return sqlite_candidates[0]

    # If .results exists but isn't sqlite, provide a clear error (often caused by output_format=log).
    head = b""
    try:
        with open(results_files[0], "rb") as f:
            head = f.read(64)
    except Exception:
        pass
    raise RuntimeError(
        "BinDiff produced a non-sqlite .results file; cannot query similarity via sqlite.\n"
        f"results_file={results_files[0]}\n"
        f"head={head!r}\n"
        "Fix: run BinDiff with sqlite output (e.g. bindiff_output_format=sqlite) or parse log output."
    )


def _is_sqlite_results_file(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            head = f.read(16)
        return head.startswith(b"SQLite format 3")
    except Exception:
        return False


def _parse_bindiff_log_function_similarities(results_path: str) -> List[float]:
    """
    Parse BinDiff log-format .results and extract per-function similarity values.

    Observed line format (tab-separated, 2-line record):
      <addr1>\\t<addr2>\\t<similarity>\\t<confidence>\\t...\\t"<name1>"\\t"<name2>"
      \\t0\\t0\\t0

    Returns a list of similarity floats for each function record found.
    """
    sims: List[float] = []
    try:
        with open(results_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except Exception as e:
        raise RuntimeError(f"Failed to read results file: {results_path}: {str(e)}") from e

    # Find the first "matched ..." section and parse function records after it.
    start_idx = None
    for i, line in enumerate(lines):
        if "matched" in line and "---------" in line:
            start_idx = i + 1
            break

    if start_idx is None:
        return sims

    for line in lines[start_idx:]:
        if not line:
            continue
        if "\t" not in line:
            continue
        # Record lines start with hex addresses; continuation lines begin with a tab.
        if line.startswith("\t") or line.startswith(" "):
            continue

        parts = line.split("\t")
        if len(parts) < 4:
            continue

        # parts[2] is similarity in observed format
        try:
            sim = float(parts[2])
        except Exception:
            continue

        sims.append(sim)

    return sims


def _find_similarity_table(conn: sqlite3.Connection) -> Optional[Tuple[str, str]]:
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cur.fetchall()]

    candidates: List[Tuple[str, str]] = []
    for table in tables:
        try:
            cur.execute(f"PRAGMA table_info('{table}')")
            cols = [row[1] for row in cur.fetchall()]
            if "similarity" in cols:
                candidates.append((table, "similarity"))
        except Exception:
            continue

    if not candidates:
        return None

    # Prefer function-related tables
    candidates.sort(key=lambda x: (0 if "function" in x[0].lower() else 1, x[0].lower()))
    return candidates[0]


def count_changed_functions(results_db: str) -> int:
    """
    Count rows where similarity != 1.0 (prefers function-related tables).
    """
    if not _is_sqlite_results_file(results_db):
        sims = _parse_bindiff_log_function_similarities(results_db)
        return sum(1 for s in sims if abs(float(s) - 1.0) > 1e-9)

    conn = sqlite3.connect(results_db)
    try:
        found = _find_similarity_table(conn)
        if not found:
            raise RuntimeError(f"Cannot find a table with 'similarity' column in: {results_db}")

        table_name, sim_col = found
        cur = conn.cursor()
        query = f"""
            SELECT COUNT(*)
            FROM "{table_name}"
            WHERE {sim_col} IS NOT NULL
              AND ABS(CAST({sim_col} AS REAL) - 1.0) > 1e-9
        """
        cur.execute(query)
        row = cur.fetchone()
        return int(row[0]) if row else 0
    finally:
        conn.close()


def count_similarity_one_functions(results_db: str) -> int:
    """
    Count rows where similarity == 1.0 (prefers function-related tables).
    """
    if not _is_sqlite_results_file(results_db):
        sims = _parse_bindiff_log_function_similarities(results_db)
        return sum(1 for s in sims if abs(float(s) - 1.0) <= 1e-9)

    conn = sqlite3.connect(results_db)
    try:
        found = _find_similarity_table(conn)
        if not found:
            raise RuntimeError(f"Cannot find a table with 'similarity' column in: {results_db}")

        table_name, sim_col = found
        cur = conn.cursor()
        query = f"""
            SELECT COUNT(*)
            FROM "{table_name}"
            WHERE {sim_col} IS NOT NULL
              AND ABS(CAST({sim_col} AS REAL) - 1.0) <= 1e-9
        """
        cur.execute(query)
        row = cur.fetchone()
        return int(row[0]) if row else 0
    finally:
        conn.close()
   
def take_screenshot(filename: str, stage="disassembly"):
    """
    获取当前屏幕截图并保存到日期目录
    
    参数:
        stage (str): 截图阶段标识，可选值:
            - "disassembly" (默认): 反汇编阶段
            - "decompilation": 反编译阶段
    
    返回:
        str: 截图文件路径，失败时返回None
    """
    try:
        # 验证stage参数
        if stage not in ["disassembly", "decompilation"]:
            raise ValueError(f"Invalid stage value: {stage}. Must be 'disassembly' or 'decompilation'")
        

        # 创建日期格式的子目录
        date_str = datetime.now().strftime('%Y%m%d')
        screenshot_dir = os.path.join(ida_output_dir, date_str, "screenshots")
        
        # 确保目录存在
        os.makedirs(screenshot_dir, exist_ok=True)
        
        # 生成带时间戳和阶段标识的文件名
        timestamp = datetime.now().strftime('%H%M%S')
        stage_marker = "asm" if stage == "disassembly" else "decomp"
        screenshot_path = os.path.join(
            screenshot_dir, 
            f"{filename}_{stage_marker}_{timestamp}.png"
        )
        
        # 获取屏幕截图
        pyautogui.screenshot(screenshot_path)
        logger.info(f"Saved {stage} screenshot to: {screenshot_path}")
        return screenshot_path
    except ValueError as ve:
        logger.error(f"Invalid parameter: {str(ve)}")
        return None
    except Exception as e:
        logger.error(f"Error taking screenshot: {str(e)}")
        return None
    

@app.route('/reversing_analyze_screenshot', methods=['POST'])
def analyze_with_screenshot():
    """分析二进制文件并返回IDA屏幕截图"""
    # 检查文件大小
    if request.content_length > MAX_FILE_SIZE:
        abort(413, "File too large (max 100MB)")
    
    # 获取IDA版本参数 (默认为ida32)
    ida_version = request.form.get('ida_version', 'ida').lower()
    if ida_version == 'ida64':
        print("Using IDA64")
        IDA_PATH = IDA64_PATH
    else:
        IDA_PATH = IDA32_PATH
    
    # 创建基于日期的目录
    date_str = datetime.now().strftime('%Y%m%d')
    analysis_dir = os.path.join(ida_output_dir, date_str)
    os.makedirs(analysis_dir, exist_ok=True)
    logger.info(f"Using analysis dir: {analysis_dir}")
    
    try:
        # 保存上传文件
        uploaded_file = request.files['file']
        if not uploaded_file or uploaded_file.filename == '':
            abort(400, "No valid file uploaded")
        
        # 保存文件到ida_output_dir下的当天日期目录
        bin_path = os.path.join(analysis_dir, uploaded_file.filename)
        uploaded_file.save(bin_path)
        logger.info(f"File saved to: {bin_path}")
        
        # 运行IDA分析
        marker_path = os.path.join(analysis_dir, "analysis_done.marker")
        cmd = [
            IDA_PATH,
            '-A',  # 自动模式
            bin_path
        ]
        print(cmd)
        
        try:
            # 启动IDA进程
            env = {
                "PATH": os.environ["PATH"],
                "SYSTEMROOT": os.environ["SYSTEMROOT"],
                "PYTHONHOME": PYTHONHOME,
                "PYTHONPATH": PYTHONPATH,
                "IDA_ANALYSIS_MARKER": marker_path
            }
            ida_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=os.environ.copy()
            )

            # ✅ 确保窗口真的出现
            wait_for_ida_window(timeout=60)
            
            '''
            # 等待IDA分析完成（检查marker文件）
            logger.info("Waiting for IDA analysis to complete...")
            start_wait = time.time()
            analysis_completed = False
            while time.time() - start_wait < 300:  # 最多等待5分钟
                if os.path.exists(marker_path):
                    analysis_completed = True
                    break
                if ida_process.poll() is not None:
                    logger.error("IDA process exited unexpectedly")
                    break
                time.sleep(1)
                
            
            if not analysis_completed:
                logger.warning("Analysis timeout or failed, proceeding with screenshots anyway")
            else:
                logger.info(f"Analysis completed in {time.time() - start_wait:.2f} seconds")
            
            '''
            # 等待IDA窗口出现
            time.sleep(10)

            # 获取反汇编的截图
            screenshot_path_1 = take_screenshot(filename=uploaded_file.filename, stage="disassembly")
            if not screenshot_path_1:
                abort(500, "Failed to capture first screenshot")

            # 模拟Tab键输入，进行反编译
            pyautogui.press('tab')
            time.sleep(5)
            
            # 获取反编译的截图
            screenshot_path_2 = take_screenshot(filename=uploaded_file.filename, stage="decompilation")
            if not screenshot_path_2:
                abort(500, "Failed to capture second screenshot")
            
            # 终止IDA进程，否则终端会卡住
            ida_process.terminate()
            try:
                ida_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                ida_process.kill()
            
            # 检查截图是否存在且非空
            if not (os.path.exists(screenshot_path_1) and os.path.exists(screenshot_path_2)):
                abort(500, "One or both screenshot files not generated")

            if os.path.getsize(screenshot_path_1) == 0 or os.path.getsize(screenshot_path_2) == 0:
                logger.error("One or both screenshot files are empty.")
                abort(500, "Screenshot files are empty or corrupted")

            
            # 创建zip文件
            zip_filename = os.path.join(analysis_dir, f"ida_screenshots_{uploaded_file.filename}.zip")
            with zipfile.ZipFile(zip_filename, 'w') as zipf:
                zipf.write(screenshot_path_1, os.path.basename(screenshot_path_1))
                zipf.write(screenshot_path_2, os.path.basename(screenshot_path_2))
            
            # 清理旧的IDA缓存文件
            clear_ida_cache(bin_path)

            # 返回zip文件
            return send_file(
                zip_filename,
                as_attachment=True,
                download_name=f"ida_screenshots_{uploaded_file.filename}.zip",
                mimetype='application/zip'
            )
            
        except subprocess.TimeoutExpired:
            abort(408, "Analysis timeout")
        except Exception as e:
            logger.error(f"Error during IDA analysis: {str(e)}")
            abort(500, f"IDA analysis error: {str(e)}")
            
    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}")
        abort(500, f"Analysis error: {str(e)}")


@app.route('/export_binexport', methods=['POST'])
def analyze():
    """
    导出 BinExport（支持两种模式）:
    1) legacy：binary_name 必须位于当天的 ida_output/<YYYYMMDD>/ 目录下
    2) direct：input_file_path 指向服务器文件系统上的二进制文件（可选 output_dir 作为工作目录）
    """
    try:
        binary_name = request.form.get("binary_name")
        input_file_path = request.form.get("input_file_path")
        output_dir = request.form.get("output_dir")
        no_zip = str(request.form.get("no_zip", "0")).strip().lower() in {"1", "true", "yes"}
        wait_analysis = str(request.form.get("wait_analysis", "1")).strip().lower() not in {"0", "false", "no"}
        force_reexport = str(request.form.get("force_reexport", "0")).strip().lower() in {"1", "true", "yes"}
        reuse_binexport = str(request.form.get("reuse_binexport", "1")).strip().lower() not in {"0", "false", "no"}

        copy_to_output_dir = str(request.form.get("copy_to_output_dir", "1")).strip().lower() not in {
            "0",
            "false",
            "no",
        }
        cleanup_param = request.form.get("cleanup")
        if cleanup_param is None:
            # 默认：只清理我们可控的工作目录（output_dir / legacy 目录）
            cleanup = bool(output_dir) or not bool(input_file_path)
        else:
            cleanup = str(cleanup_param).strip().lower() not in {"0", "false", "no"}

        if not binary_name and input_file_path:
            binary_name = os.path.basename(input_file_path.replace("\\", "/"))

        if not binary_name:
            abort(400, "Missing binary_name (or input_file_path)")
        
        # 获取IDA版本参数 (默认为ida32)
        ida_version = request.form.get('ida_version', 'ida').lower()
        
        # 构建当天日期目录路径
        date_str = datetime.now().strftime('%Y%m%d')
        analysis_dir = os.path.join(ida_output_dir, date_str)
        os.makedirs(analysis_dir, exist_ok=True)
        
        try:
            if input_file_path:
                if output_dir:
                    work_dir = os.path.abspath(output_dir)
                    bin_path = _prepare_working_binary(
                        input_file_path=input_file_path,
                        work_dir=work_dir,
                        copy_to_work_dir=copy_to_output_dir,
                    )
                else:
                    # in-place：不拷贝，工作目录为二进制所在目录
                    bin_path = os.path.abspath(input_file_path)
                    work_dir = os.path.dirname(bin_path)
            else:
                # legacy：二进制必须已在当天目录
                work_dir = analysis_dir
                bin_path = os.path.join(analysis_dir, binary_name)
                if not os.path.exists(bin_path):
                    abort(404, f"Binary file not found: {binary_name}")

            logger.info(f"Found target file: {bin_path}")

            extra_dirs: List[str] = []
            # If user passes bindiff_cli, add its directory to PATH for plugin dependencies.
            bindiff_cli_req = request.form.get("bindiff_cli")
            if bindiff_cli_req:
                bd_dir = os.path.dirname(os.path.abspath(bindiff_cli_req))
                if bd_dir:
                    extra_dirs.append(bd_dir)

            export_path, idb_path = _run_ida_binexport(
                bin_path=bin_path,
                work_dir=work_dir,
                ida_version=ida_version,
                timeout_sec=3600,
                extra_path_dirs=extra_dirs,
                wait_analysis=wait_analysis,
                reuse_existing=reuse_binexport,
                force_reexport=force_reexport,
            )
        except subprocess.TimeoutExpired:
            abort(408, "Analysis timeout")
        
        logger.info(f"Analysis completed successfully")

        if no_zip:
            return jsonify(
                {
                    "binary_name": binary_name,
                    "bin_path": bin_path,
                    "work_dir": work_dir,
                    "binexport_path": export_path,
                    "idb_path": idb_path,
                }
            )

        # 创建 zip 文件（BinExport 必须打包，IDB 有就顺便打进去）
        zip_filename = os.path.join(work_dir, f"ida_analysis_{binary_name}.zip")
        with zipfile.ZipFile(zip_filename, 'w') as zipf:
            zipf.write(export_path, os.path.basename(export_path))
            if idb_path:
                zipf.write(idb_path, os.path.basename(idb_path))

        # 清理旧的IDA缓存文件
        if cleanup:
            clear_ida_cache(bin_path)

        # 返回zip文件
        return send_file(
            zip_filename,
            as_attachment=True,
            download_name=f"ida_analysis_{binary_name}.zip",
            mimetype='application/zip'
        )
        
        
    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}", exc_info=True)
        abort(500, f"Analysis error: {str(e)}")


@app.route("/batch_bindiff_modified", methods=["POST"])
def batch_bindiff_modified():
    """
    批量对补丁前/后的二进制做 BinDiff，并统计 similarity != 1.0 的函数数量之和。

    目录约定（任选其一传参）：
    - task_dir: <task_dir>/extracted_diff_files/modified/{old,new}/
    - modified_dir: <modified_dir>/{old,new}/
    - old_dir + new_dir: 显式指定

    文件命名约定：old_XXX 与 new_XXX 成对（可通过 old_prefix/new_prefix 修改）。

    可选参数：
    - output_dir: 输出/缓存目录，默认 <task_dir>/bindiff_batch_cache 或 <modified_dir>/bindiff_batch_cache
    - ida_version: ida / ida64（默认 ida）
    - bindiff_cli: BinDiff 命令行路径（默认使用 BINDIFF_CLI 或环境变量 BINDIFF_CLI）
    - copy_to_output_dir: 是否复制二进制到缓存目录再跑 IDA（默认 1）
    """
    try:
        data = request.get_json(silent=True) if request.is_json else request.form

        def _get(name: str, default=None):
            try:
                return data.get(name, default) if data is not None else default
            except Exception:
                return default

        task_dir = _get("task_dir")
        modified_dir = _get("modified_dir")
        old_dir = _get("old_dir")
        new_dir = _get("new_dir")

        old_prefix = _get("old_prefix", "old_")
        new_prefix = _get("new_prefix", "new_")
        ida_version = _get("ida_version", "ida")
        bindiff_cli = _get("bindiff_cli", None) or BINDIFF_CLI
        wait_analysis = str(_get("wait_analysis", "1")).strip().lower() not in {"0", "false", "no"}
        bindiff_output_format = _get("bindiff_output_format", "log")
        reuse_binexport = str(_get("reuse_binexport", "1")).strip().lower() not in {"0", "false", "no"}
        force_reexport = str(_get("force_reexport", "0")).strip().lower() in {"1", "true", "yes"}

        copy_to_output_dir = str(_get("copy_to_output_dir", "1")).strip().lower() not in {
            "0",
            "false",
            "no",
        }

        if not old_dir or not new_dir:
            if task_dir:
                old_dir = os.path.join(task_dir, "extracted_diff_files", "modified", "old")
                new_dir = os.path.join(task_dir, "extracted_diff_files", "modified", "new")
            elif modified_dir:
                old_dir = os.path.join(modified_dir, "old")
                new_dir = os.path.join(modified_dir, "new")

        if not old_dir or not new_dir:
            abort(400, "Missing parameters: provide task_dir or modified_dir or (old_dir + new_dir)")

        if not os.path.isdir(old_dir):
            abort(404, f"old_dir not found: {old_dir}")
        if not os.path.isdir(new_dir):
            abort(404, f"new_dir not found: {new_dir}")

        if task_dir:
            default_out = os.path.join(task_dir, "bindiff_batch_cache")
        elif modified_dir:
            default_out = os.path.join(modified_dir, "bindiff_batch_cache")
        else:
            default_out = os.path.join(os.path.dirname(os.path.abspath(old_dir)), "bindiff_batch_cache")

        output_dir = os.path.abspath(_get("output_dir", default_out))
        ensure_dir(output_dir)

        pairs = list_old_new_pairs(old_dir, new_dir, old_prefix=old_prefix, new_prefix=new_prefix)
        logger.info(f"[BatchBinDiff] pairs={len(pairs)} old_dir={old_dir} new_dir={new_dir} out={output_dir}")

        old_export_root = os.path.join(output_dir, "binexports", "old")
        new_export_root = os.path.join(output_dir, "binexports", "new")
        bindiff_root = os.path.join(output_dir, "bindiff_results")
        ensure_dir(old_export_root)
        ensure_dir(new_export_root)
        ensure_dir(bindiff_root)

        summary = []
        total_changed_functions_sum = 0
        total_similarity_one_functions_sum = 0

        for idx, (pair_key, old_bin, new_bin) in enumerate(pairs, 1):
            logger.info(f"[BatchBinDiff] [{idx}/{len(pairs)}] {pair_key}")

            old_dir_pair = os.path.join(old_export_root, pair_key)
            new_dir_pair = os.path.join(new_export_root, pair_key)
            bindiff_dir_pair = os.path.join(bindiff_root, pair_key)
            ensure_dir(old_dir_pair)
            ensure_dir(new_dir_pair)
            ensure_dir(bindiff_dir_pair)

            row = {
                "pair_key": pair_key,
                "old_binary": old_bin,
                "new_binary": new_bin,
                "old_binexport": None,
                "new_binexport": None,
                "results_db": None,
                "changed_functions": None,
                "similarity_one_functions": None,
                "status": "failed",
                "error": None,
            }

            try:
                old_local = _prepare_working_binary(old_bin, old_dir_pair, copy_to_work_dir=copy_to_output_dir)
                new_local = _prepare_working_binary(new_bin, new_dir_pair, copy_to_work_dir=copy_to_output_dir)

                bindiff_cli_dir = os.path.dirname(os.path.abspath(bindiff_cli)) if bindiff_cli else ""
                extra_dirs = [bindiff_cli_dir] if bindiff_cli_dir else None

                old_be, _old_idb = _run_ida_binexport(
                    old_local,
                    old_dir_pair,
                    ida_version=ida_version,
                    timeout_sec=3600,
                    extra_path_dirs=extra_dirs,
                    wait_analysis=wait_analysis,
                    reuse_existing=reuse_binexport,
                    force_reexport=force_reexport,
                )
                new_be, _new_idb = _run_ida_binexport(
                    new_local,
                    new_dir_pair,
                    ida_version=ida_version,
                    timeout_sec=3600,
                    extra_path_dirs=extra_dirs,
                    wait_analysis=wait_analysis,
                    reuse_existing=reuse_binexport,
                    force_reexport=force_reexport,
                )
                row["old_binexport"] = old_be
                row["new_binexport"] = new_be

                # 清理掉 IDB/i64 等缓存（保留 BinExport 供 bindiff 使用）
                clear_ida_cache(old_local)
                clear_ida_cache(new_local)

                results_db = _run_bindiff_cli(
                    old_be,
                    new_be,
                    bindiff_dir_pair,
                    bindiff_cli=bindiff_cli,
                    timeout_sec=3600,
                    output_format=bindiff_output_format,
                )
                row["results_db"] = results_db
                changed_count = count_changed_functions(results_db)
                sim1_count = count_similarity_one_functions(results_db)

                row["changed_functions"] = changed_count
                row["similarity_one_functions"] = sim1_count
                row["status"] = "success"

                total_changed_functions_sum += changed_count
                total_similarity_one_functions_sum += sim1_count
            except Exception as e:
                row["error"] = str(e)

            summary.append(row)

        summary_path = os.path.join(output_dir, "bindiff_summary.json")
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "old_dir": old_dir,
                    "new_dir": new_dir,
                    "total_pairs": len(pairs),
                    "total_changed_functions_sum": total_changed_functions_sum,
                    "total_similarity_one_functions_sum": total_similarity_one_functions_sum,
                    "details": summary,
                },
                f,
                ensure_ascii=False,
                indent=2,
            )

        return jsonify(
            {
                "old_dir": old_dir,
                "new_dir": new_dir,
                "output_dir": output_dir,
                "total_pairs": len(pairs),
                "total_changed_functions_sum": total_changed_functions_sum,
                "total_similarity_one_functions_sum": total_similarity_one_functions_sum,
                "summary_path": summary_path,
                "details": summary,
            }
        )

    except Exception as e:
        logger.error(f"Error in batch_bindiff_modified: {str(e)}", exc_info=True)
        abort(500, f"batch_bindiff_modified error: {str(e)}")


def convert_size(size_bytes):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} TB"


@app.route('/export_pseudo_c', methods=['POST'])
def export_pseudo_c():
    """根据文件名导出二进制文件的伪C代码"""
    try:
        # 获取请求参数
        binary_name = request.form.get('binary_name')
        if not binary_name:
            abort(400, "No binary name provided")

        # 获取IDA版本参数 (默认为ida32)
        ida_version = request.form.get('ida_version', 'ida').lower()
        if ida_version == 'ida64':
            logger.info("Using IDA64")
            IDAT_PATH = IDAT64_PATH
        else:
            IDAT_PATH = IDAT32_PATH

        # 构建当天日期目录路径
        date_str = datetime.now().strftime('%Y%m%d')
        analysis_dir = os.path.join(ida_output_dir, date_str)
        source_output_dir = os.path.join(analysis_dir, "source")
        os.makedirs(source_output_dir, exist_ok=True)

        # 查找目标文件
        bin_path = os.path.join(analysis_dir, binary_name)
        if not bin_path:
            abort(404, f"Binary file not found: {binary_name}")

        logger.info(f"Found target file: {bin_path}")

        # 运行IDA分析
        cmd = [
            IDAT_PATH,
            '-A',  # 自动模式
            '-T',  # 不显示界面
            f'-S\"{EXPORT_SCRIPT}\"',
            bin_path
        ]
        logger.info(f"Executing: {' '.join(cmd)}")
        
        start_time = time.time()
        try:
            result = subprocess.run(
                cmd,
                # cwd=analysis_dir,  # 在工作目录执行
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=TIMEOUT,
                env=os.environ.copy()
            )
        except subprocess.TimeoutExpired:
            # abort(408, "Export pseudo C timeout")
            logger.warning("Export pseudo C timeout")
        
        end_time = time.time()

        stdout_text = result.stdout.decode(errors="ignore").strip()
        stderr_text = result.stderr.decode(errors="ignore").strip()
        logger.info(f"[PseudoC] stdout for {binary_name}:\n{stdout_text}")
        logger.info(f"[PseudoC] stderr for {binary_name}:\n{stderr_text}")

        if result.returncode != 0:
            logger.error(f"[PseudoC] IDA exited with code {result.returncode}")
            abort(500, f"Pseudo C export failed: {stderr_text or stdout_text or 'unknown error'}")

        
        # 再次检查输出文件
        output_filepath = os.path.join(analysis_dir, f"{binary_name}_pseudo.c")
        if not os.path.exists(output_filepath) or os.path.getsize(output_filepath) == 0:
            logger.error(f"Pseudo C file not found or empty: {output_filepath}")
            abort(500, f"Pseudo C file not generated or empty: {output_filepath}")

        
        pseudo_filepath = os.path.join(source_output_dir, f"{binary_name}_pseudo.c")
        if os.path.exists(pseudo_filepath):
            os.remove(pseudo_filepath)
        shutil.move(output_filepath, source_output_dir)
        

        logger.info(f"{binary_name} Exported pseudo C completed, size: {convert_size(os.path.getsize(bin_path))}")
        logger.info(f"Export time: {end_time - start_time:.2f} seconds")

        # 清理旧的IDA缓存文件
        clear_ida_cache(bin_path)

        # 返回生成的伪C代码文件
        return send_file(
            pseudo_filepath,
            as_attachment=True,
            download_name=os.path.basename(pseudo_filepath),
            mimetype='text/plain'
        )

    except Exception as e:
        logger.error(f"Error during pseudo C export: {str(e)}", exc_info=True)
        abort(500, f"Pseudo C export error: {str(e)}")
     

@app.route('/get_function_call_info', methods=['POST'])
def get_function_call_info():
    """获取特定函数的调用链信息"""
    try:
        # 获取请求参数
        binary_name = request.form.get('binary_name')
        function_name = request.form.get('function_name')
        
        if not binary_name or not function_name:
            abort(400, "Missing required parameters: binary_name or function_name")

        # 获取IDA版本参数 (默认为ida32)
        ida_version = request.form.get('ida_version', 'ida').lower()
        if ida_version == 'ida64':
            logger.info("Using IDA64 for function call info")
            ida_path = IDA64_PATH
        else:
            ida_path = IDA32_PATH

        # 构建当天日期目录路径
        date_str = datetime.now().strftime('%Y%m%d')
        analysis_dir = os.path.join(ida_output_dir, date_str)
        # 确保工作目录存在，避免 Windows 下 cwd 非法导致 [WinError 267]
        os.makedirs(analysis_dir, exist_ok=True)
        
        # 查找目标文件（支持绝对路径或位于 analysis_dir 的文件名）
        bin_path = os.path.join(analysis_dir, binary_name)
        if not os.path.exists(bin_path):
            abort(404, f"Binary file not found: {binary_name}")
            print("[DEBUG][get_function_call_info] binary_name=", binary_name)

        logger.info(f"Getting call info for function {function_name} in file {bin_path}")
        
        # 调用IDA运行analyze.py分析目标函数
        try:
            # 构建IDA命令
            # 注意：不在 -S 参数中传递 --func，而是通过环境变量 IDA_FUNC_NAME 传递
            # Windows下需要特别注意引号的处理
            cmd = [
                ida_path,
                '-A',  # 自动模式
                f'-S{ANALYZE_SCRIPT}',  # 注意：移除引号，因为subprocess.run会自动处理路径
                bin_path
            ]
            
            logger.info(f"Running IDA command: {' '.join(cmd)}")
            logger.info(f"Function name passed via IDA_FUNC_NAME environment variable: {function_name}")
            
            # 执行命令，通过环境变量传递函数名
            proc_env = os.environ.copy()
            proc_env["IDA_FUNC_NAME"] = function_name  # 通过环境变量传递函数名
            
            logger.debug(f"Environment variables: IDA_FUNC_NAME={function_name}")

            result = subprocess.run(
                cmd,
                cwd=analysis_dir,  # 在工作目录执行
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=TIMEOUT,
                env=proc_env,
            )
            
            stdout_text = result.stdout.decode(errors='ignore').strip()
            stderr_text = result.stderr.decode(errors='ignore').strip()

            if stdout_text:
                logger.info(f"IDA stdout: {stdout_text}")
            if stderr_text:
                logger.info(f"IDA stderr: {stderr_text}")

            # 检查执行结果
            if result.returncode != 0:
                error_msg = stderr_text or stdout_text or f"IDA exited with code {result.returncode}"
                logger.error(f"IDA Error (code {result.returncode}): {error_msg}")
                abort(500, f"IDA analysis failed: {error_msg}")

            # 查找分析结果 JSON（analyze.py 产出）
            json_files = []
            for filename in os.listdir(analysis_dir):
                if not filename.endswith(".json"):
                    continue
                if not (filename.startswith("ida_slice_") or filename.startswith("ida_combined_analysis_")):
                    continue
                if function_name in filename:
                    json_files.append(os.path.join(analysis_dir, filename))

            if not json_files:
                # Fallback: 如果没找到带函数名的文件，则接受任意 slice/combined json
                for filename in os.listdir(analysis_dir):
                    if not filename.endswith(".json"):
                        continue
                    if not (filename.startswith("ida_slice_") or filename.startswith("ida_combined_analysis_")):
                        continue
                    json_files.append(os.path.join(analysis_dir, filename))

            if not json_files:
                try:
                    files = os.listdir(analysis_dir)
                except Exception as e:
                    files = [f"(failed to list dir: {str(e)})"]

                detail_msg = (
                    "Analysis result file not found.\n"
                    f"function_name={function_name}\n"
                    f"analysis_dir={analysis_dir}\n"
                    f"candidates={json_files}\n"
                    f"dir_listing={files}"
                )
                logger.error(detail_msg)
                abort(500, detail_msg)

            json_files.sort(key=os.path.getmtime, reverse=True)
            result_file = json_files[0]

            with open(result_file, "r", encoding="utf-8") as f:
                analysis_result = json.load(f)

            logger.info(f"Successfully retrieved call info for function {function_name}")
            return jsonify(analysis_result), 200

        except subprocess.TimeoutExpired:
            logger.error("IDA analysis timed out")
            abort(408, "Analysis timeout")
        except Exception as e:
            logger.error(f"Error getting function call info: {str(e)}", exc_info=True)
            abort(500, f"Failed to get function call info: {str(e)}")

    except Exception as e:
        logger.error(f"Error in get_function_call_info: {str(e)}", exc_info=True)
        abort(500, f"Internal server error: {str(e)}")


if __name__ == "__main__":
    # 以脚本方式启动 Flask 服务
    app.run(host="0.0.0.0", port=port)
