"""
Batch runner for the full llm_diff pipeline.

This script reuses the Case list from agent/run_ablation_batch.py and runs the
current agent/llm_diff.py end-to-end without any ablation filtering.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


from agent import llm_diff
from agent.run_ablation_batch import CASES, Case


def _reset_llm_stats() -> None:
    from agent.llm_stats import LLM_STATS

    LLM_STATS.total_prompt_tokens = 0
    LLM_STATS.total_completion_tokens = 0
    LLM_STATS.total_calls = 0
    LLM_STATS.total_time = 0.0
    LLM_STATS.records = []
    LLM_STATS.model_totals = {}


def _truthy_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw.strip())
    except Exception:
        return default


def _now_ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _log_line(fp: Path, line: str) -> None:
    fp.parent.mkdir(parents=True, exist_ok=True)
    with open(fp, "a", encoding="utf-8") as f:
        f.write(f"[{_now_ts()}] {line}\n")


def _copy2(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.exists():
        shutil.copy2(src, dst)


def _bindiff_root(case: Case, binary_name: str) -> Path:
    return Path(case.history_root).expanduser().resolve() / case.chat_id / "bindiff" / binary_name


def _infer_bindiff_source_binary(case: Case) -> str:
    try:
        pre_parent = Path(case.pre_c).resolve().parent.name
        if pre_parent:
            return pre_parent
    except Exception:
        pass
    return case.binary_filename


def _ensure_case_results(case: Case) -> str:
    target_root = _bindiff_root(case, case.binary_filename)
    target_root.mkdir(parents=True, exist_ok=True)
    target_results = sorted(target_root.glob("*.results"))
    if target_results:
        return case.binary_filename

    source_binary = _infer_bindiff_source_binary(case)
    source_root = _bindiff_root(case, source_binary)
    source_results = sorted(source_root.glob("*.results")) if source_root.exists() else []
    if not source_results:
        return case.binary_filename

    for src in source_results:
        shutil.copy2(src, target_root / src.name)
    return source_binary


def _snapshot_diff_dirs(case: Case) -> set[str]:
    bindiff_root = _bindiff_root(case, case.binary_filename)
    if not bindiff_root.exists():
        return set()
    return {p.name for p in bindiff_root.iterdir() if p.is_dir() and p.name.startswith("diff_")}


def _find_new_output_dir(case: Case, before: set[str]) -> Path | None:
    bindiff_root = _bindiff_root(case, case.binary_filename)
    if not bindiff_root.exists():
        return None

    current = [p for p in bindiff_root.iterdir() if p.is_dir() and p.name.startswith("diff_")]
    new_dirs = [p for p in current if p.name not in before]
    if new_dirs:
        return max(new_dirs, key=lambda p: p.stat().st_mtime)
    if current:
        return max(current, key=lambda p: p.stat().st_mtime)
    return None


def _find_attempt_output_dir(case: Case, before: set[str]) -> Path | None:
    bindiff_root = _bindiff_root(case, case.binary_filename)
    if not bindiff_root.exists():
        return None

    current = [p for p in bindiff_root.iterdir() if p.is_dir() and p.name.startswith("diff_")]
    new_dirs = [p for p in current if p.name not in before]
    if not new_dirs:
        return None
    return max(new_dirs, key=lambda p: p.stat().st_mtime)


async def _run_with_live_pt_sync(
    case: Case,
    *,
    case_dir: Path,
    batch_log: Path,
    before_dirs: set[str],
    sync_interval_seconds: float,
    heartbeat_seconds: float,
) -> Path | None:
    output_dir: Path | None = None
    live_pt_target = case_dir / "pt.log"
    last_synced_signature: tuple[int, int] | None = None
    last_heartbeat = time.time()
    start_time = last_heartbeat

    task = asyncio.create_task(
        llm_diff.main(
            chat_id=case.chat_id,
            history_root=case.history_root,
            binary_filename=case.binary_filename,
            post_binary_filename=case.post_binary_filename,
            pre_c=case.pre_c,
            post_c=case.post_c,
            cve_details=case.cve_details,
            cwe=case.cwe,
            ablation_strategy=4,
        )
    )

    while not task.done():
        if output_dir is None:
            output_dir = _find_attempt_output_dir(case, before_dirs)
            if output_dir is not None:
                _log_line(batch_log, f"detected OUTPUT_DIR={output_dir}")

        if output_dir is not None:
            src_pt = output_dir / "pt.log"
            if src_pt.exists():
                try:
                    stat = src_pt.stat()
                    signature = (stat.st_size, stat.st_mtime_ns)
                    if signature != last_synced_signature:
                        _copy2(src_pt, live_pt_target)
                        last_synced_signature = signature
                except Exception as e:
                    _log_line(batch_log, f"pt.log live sync warning: {type(e).__name__}: {e}")

        now = time.time()
        if now - last_heartbeat >= heartbeat_seconds:
            elapsed = round(now - start_time, 1)
            output_desc = str(output_dir) if output_dir is not None else "pending"
            _log_line(batch_log, f"still_running elapsed={elapsed}s output_dir={output_desc}")
            last_heartbeat = now

        await asyncio.sleep(sync_interval_seconds)

    await task

    if output_dir is None:
        output_dir = _find_new_output_dir(case, before_dirs)

    if output_dir is not None:
        src_pt = output_dir / "pt.log"
        if src_pt.exists():
            _copy2(src_pt, live_pt_target)

    return output_dir


async def _run_case(case: Case, *, out_root: Path) -> None:
    case_dir = out_root / case.binary_filename
    case_dir.mkdir(parents=True, exist_ok=True)
    batch_log = case_dir / "batch_run.log"

    continue_on_error = _truthy_env("VULN_LLM_BATCH_CONTINUE_ON_ERROR", True)
    skip_existing = _truthy_env("VULN_LLM_BATCH_SKIP_EXISTING", False)
    max_attempts = max(1, _int_env("VULN_LLM_BATCH_MAX_ATTEMPTS", 1))
    sync_interval_seconds = max(1, _int_env("VULN_LLM_BATCH_SYNC_SECONDS", 5))
    heartbeat_seconds = max(sync_interval_seconds, _int_env("VULN_LLM_BATCH_HEARTBEAT_SECONDS", 30))

    manifest: Dict[str, Any] = {
        "binary_filename": case.binary_filename,
        "post_binary_filename": case.post_binary_filename,
        "chat_id": case.chat_id,
        "history_root": case.history_root,
        "settings": {
            "continue_on_error": continue_on_error,
            "skip_existing": skip_existing,
            "max_attempts": max_attempts,
        },
        "runs": [],
    }

    key_artifact = case_dir / "global_attribution_tournament.json"
    if skip_existing and key_artifact.exists():
        msg = f"[Batch] {case.binary_filename}: skipped (artifact exists: {key_artifact.name})."
        print(msg, flush=True)
        _log_line(batch_log, msg)
        manifest["runs"].append({"status": "skipped", "reason": f"artifact_exists:{key_artifact.name}"})
        with open(case_dir / "run_manifest.json", "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)
        return

    copied_from = _ensure_case_results(case)
    run_entry: Dict[str, Any] = {
        "status": "started",
        "missing_artifacts": [],
        "results_source_binary": copied_from,
    }
    run_start = time.time()

    print(f"[Batch] {case.binary_filename}: full llm_diff ...", flush=True)
    _log_line(batch_log, f"START results_source_binary={copied_from}")
    _reset_llm_stats()

    try:
        last_error: str | None = None
        output_dir: Path | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                before_dirs = _snapshot_diff_dirs(case)
                _log_line(batch_log, f"attempt={attempt}/{max_attempts} running llm_diff.main()")
                output_dir = await _run_with_live_pt_sync(
                    case,
                    case_dir=case_dir,
                    batch_log=batch_log,
                    before_dirs=before_dirs,
                    sync_interval_seconds=sync_interval_seconds,
                    heartbeat_seconds=heartbeat_seconds,
                )
                last_error = None
                break
            except Exception as e:
                last_error = f"{type(e).__name__}: {e}"
                _log_line(batch_log, f"attempt={attempt} FAILED: {last_error}")
                if attempt < max_attempts:
                    await asyncio.sleep(min(10, 2 * attempt))

        if last_error is not None:
            raise RuntimeError(last_error)

        if output_dir is None:
            raise RuntimeError("unable to locate llm_diff output directory")

        run_entry["OUTPUT_DIR"] = str(output_dir.resolve())

        artifact_names = [
            "global_attribution_tournament.json",
            "pt.log",
            "vuln_analysis_results.json",
        ]
        for name in artifact_names:
            src = output_dir / name
            if src.exists():
                target_name = name
                _copy2(src, case_dir / target_name)
            else:
                run_entry["missing_artifacts"].append(str(src))

        ctx_log = output_dir / "vuln_analysis_results.json.ctx"
        if ctx_log.exists():
            _copy2(ctx_log, case_dir / ctx_log.name)

        run_entry["status"] = "completed"
        print(f"[Batch] {case.binary_filename}: done.", flush=True)
        _log_line(batch_log, f"END status=completed missing={len(run_entry['missing_artifacts'])}")
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
        run_entry["status"] = "failed"
        run_entry["error"] = err
        _log_line(batch_log, f"END status=failed error={err}")
        print(f"[Batch] {case.binary_filename}: FAILED: {err}", flush=True)
        if not continue_on_error:
            manifest["runs"].append(run_entry)
            raise
    finally:
        run_entry["wall_time_seconds"] = round(time.time() - run_start, 4)
        manifest["runs"].append(run_entry)
        with open(case_dir / "run_manifest.json", "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)


async def main() -> None:
    out_root_env = os.environ.get("VULN_LLM_BATCH_OUT_ROOT", "").strip()
    out_root = Path(out_root_env) if out_root_env else REPO_ROOT / "llm_diff_outputs_deepseek"
    out_root.mkdir(parents=True, exist_ok=True)

    for case in CASES:
        await _run_case(case, out_root=out_root)


if __name__ == "__main__":
    asyncio.run(main())
