"""
Batch runner for ablation strategies (1/2/3/4) on multiple CVE binaries.

Runs llm_diff.main() four times per case with ablation_strategy=1..4 and
collects the key artifacts into:

  <repo_root>/ablation_outputs/<binary_filename>/

Artifacts copied per strategy:
  - strategy 1/2/3: direct_root_cause_top20_strategy{n}.json
  - strategy 4:     global_attribution_tournament.json
  - all strategies: pt.log  -> pt_strategy{n}.log
  - all strategies: vuln_analysis_results.json -> vuln_analysis_results_strategy{n}.json
  - manifest: run_manifest.json
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@dataclass(frozen=True)
class Case:
    chat_id: str
    history_root: str
    binary_filename: str
    post_binary_filename: str
    pre_c: str
    post_c: str
    cve_details: str
    cwe: str


CASES: List[Case] = [
    Case(chat_id="paper-3.16",
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2022-36480cstecgi",
        post_binary_filename = "CVE-2022-36480cstecgi1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2022-36480cstecgi\CVE-2022-36480cstecgi.cgi_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2022-36480cstecgi\CVE-2022-36480cstecgi1.cgi_pseudo.c",
        cve_details="TOTOLINK N350RT V9.3.5u.6139_B20201216 was discovered to contain a command injection vulnerability via the command parameter",
        cwe="CWE-78"),
]


def _reset_llm_stats() -> None:
    from agent.llm_stats import LLM_STATS

    LLM_STATS.total_prompt_tokens = 0
    LLM_STATS.total_completion_tokens = 0
    LLM_STATS.total_calls = 0
    LLM_STATS.total_time = 0.0
    LLM_STATS.records = []
    LLM_STATS.model_totals = {}


def _copy2(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.exists():
        shutil.copy2(src, dst)


def _now_ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _log_line(fp: Path, line: str) -> None:
    fp.parent.mkdir(parents=True, exist_ok=True)
    with open(fp, "a", encoding="utf-8") as f:
        f.write(f"[{_now_ts()}] {line}\n")


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


async def _run_case(case: Case, *, out_root: Path) -> None:
    from agent import llm_diff

    case_dir = out_root / case.binary_filename
    case_dir.mkdir(parents=True, exist_ok=True)
    batch_log = case_dir / "batch_run.log"

    continue_on_error = _truthy_env("VULN_BATCH_CONTINUE_ON_ERROR", True)
    skip_existing = _truthy_env("VULN_BATCH_SKIP_EXISTING", False)
    max_attempts = max(1, _int_env("VULN_BATCH_MAX_ATTEMPTS", 1))

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

    strategy3_output_dir: Path | None = None

    strategies_env = os.environ.get("VULN_BATCH_STRATEGIES", "").strip()
    if strategies_env:
        parsed: List[int] = []
        for part in strategies_env.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                parsed.append(int(part))
            except Exception:
                continue
        strategies = [s for s in parsed if s in (1, 2, 3, 4)] or [1, 2, 3, 4]
    else:
        strategies = [1, 2, 3, 4]

    for strategy in strategies:
        _reset_llm_stats()

        if skip_existing:
            key_dst = (
                (case_dir / f"direct_root_cause_top20_strategy{strategy}.json")
                if strategy in (1, 2, 3)
                else (case_dir / "global_attribution_tournament.json")
            )
            if key_dst.exists():
                msg = f"[Batch] {case.binary_filename}: strategy {strategy} skipped (artifact exists: {key_dst.name})."
                print(msg, flush=True)
                _log_line(batch_log, msg)
                manifest["runs"].append(
                    {
                        "strategy": strategy,
                        "status": "skipped",
                        "reason": f"artifact_exists:{key_dst.name}",
                    }
                )
                continue

        reuse_structured_results: str | None = None
        if strategy == 4:
            if strategy3_output_dir is not None and strategy3_output_dir.exists():
                reuse_structured_results = str(strategy3_output_dir)
            else:
                cached = case_dir / "structured_results_strategy3.json"
                if cached.exists():
                    reuse_structured_results = str(cached)

        print(f"[Batch] {case.binary_filename}: strategy {strategy} ...", flush=True)
        _log_line(batch_log, f"START strategy={strategy}")

        run_entry: Dict[str, Any] = {"strategy": strategy, "status": "started", "missing_artifacts": []}
        run_start = time.time()
        output_dir: Path | None = None
        result: Dict[str, Any] | None = None

        try:
            last_error: str | None = None
            for attempt in range(1, max_attempts + 1):
                try:
                    _log_line(batch_log, f"strategy={strategy} attempt={attempt}/{max_attempts} running llm_diff.main()")
                    result = await llm_diff.main(
                        chat_id=case.chat_id,
                        history_root=case.history_root,
                        binary_filename=case.binary_filename,
                        post_binary_filename=case.post_binary_filename,
                        pre_c=case.pre_c,
                        post_c=case.post_c,
                        cve_details=case.cve_details,
                        cwe=case.cwe,
                        ablation_strategy=strategy,
                        reuse_structured_results_json=reuse_structured_results,
                    )
                    last_error = None
                    break
                except Exception as e:
                    last_error = f"{type(e).__name__}: {e}"
                    _log_line(batch_log, f"strategy={strategy} attempt={attempt} FAILED: {last_error}")
                    if attempt < max_attempts:
                        await asyncio.sleep(min(10, 2 * attempt))
            if result is None:
                raise RuntimeError(last_error or "llm_diff.main() failed with unknown error")

            output_dir = Path(result.get("OUTPUT_DIR", "")).resolve()
            if strategy == 3:
                strategy3_output_dir = output_dir
            run_entry.update(
                {
                    "OUTPUT_DIR": str(output_dir),
                    "LOG_FILE": result.get("LOG_FILE"),
                    "RESULTS_FILE": result.get("RESULTS_FILE"),
                }
            )
            if reuse_structured_results:
                run_entry["reuse_structured_results_json"] = reuse_structured_results

            if strategy in (1, 2, 3):
                src_json = output_dir / f"direct_root_cause_top20_strategy{strategy}.json"
                if src_json.exists():
                    _copy2(src_json, case_dir / src_json.name)
                else:
                    run_entry["missing_artifacts"].append(str(src_json))
            else:
                src_tournament = output_dir / "global_attribution_tournament.json"
                if src_tournament.exists():
                    _copy2(src_tournament, case_dir / src_tournament.name)
                else:
                    run_entry["missing_artifacts"].append(str(src_tournament))

            src_pt = output_dir / "pt.log"
            if src_pt.exists():
                _copy2(src_pt, case_dir / f"pt_strategy{strategy}.log")
            else:
                run_entry["missing_artifacts"].append(str(src_pt))

            src_results = output_dir / "vuln_analysis_results.json"
            if src_results.exists():
                _copy2(src_results, case_dir / f"vuln_analysis_results_strategy{strategy}.json")

            src_struct = output_dir / "structured_results.json"
            if src_struct.exists():
                _copy2(src_struct, case_dir / f"structured_results_strategy{strategy}.json")

            run_entry["status"] = "completed"
            print(f"[Batch] {case.binary_filename}: strategy {strategy} done.", flush=True)
            _log_line(batch_log, f"END strategy={strategy} status=completed missing={len(run_entry['missing_artifacts'])}")

        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            run_entry["status"] = "failed"
            run_entry["error"] = err
            _log_line(batch_log, f"END strategy={strategy} status=failed error={err}")
            print(f"[Batch] {case.binary_filename}: strategy {strategy} FAILED: {err}", flush=True)
            if not continue_on_error:
                manifest["runs"].append(run_entry)
                raise
        finally:
            run_end = time.time()
            run_entry["wall_time_seconds"] = round(run_end - run_start, 4)
            manifest["runs"].append(run_entry)

    with open(case_dir / "run_manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)


async def main() -> None:
    out_root = REPO_ROOT / "ablation_outputs"
    out_root.mkdir(parents=True, exist_ok=True)

    for case in CASES:
        await _run_case(case, out_root=out_root)


if __name__ == "__main__":
    asyncio.run(main())
