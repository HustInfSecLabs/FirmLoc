#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
        binary_filename="CVE-2024-57012cstecgi",
        post_binary_filename = "CVE-2024-57020cstecgi1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2024-57020cstecgi\CVE-2024-57020cstecgi.cgi_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2024-57020cstecgi\CVE-2024-57020cstecgi1.cgi_pseudo.c",
        cve_details="TOTOLINK X5000R V9.1.0cu.2350_B20230313 was discovered to contain an OS command injection vulnerability via the week parameter",
        cwe="CWE-78"),

Case(chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2024-57013cstecgi",
        post_binary_filename = "CVE-2024-57020cstecgi1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2024-57020cstecgi\CVE-2024-57020cstecgi.cgi_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2024-57020cstecgi\CVE-2024-57020cstecgi1.cgi_pseudo.c",
        cve_details="TOTOLINK X5000R V9.1.0cu.2350_B20230313 was discovered to contain an OS command injection vulnerability via the switch parameter",
        cwe="CWE-78"),

Case(chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2024-57014cstecgi",
        post_binary_filename = "CVE-2024-57020cstecgi1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2024-57020cstecgi\CVE-2024-57020cstecgi.cgi_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2024-57020cstecgi\CVE-2024-57020cstecgi1.cgi_pseudo.c",
        cve_details="TOTOLINK X5000R V9.1.0cu.2350_B20230313 was discovered to contain an OS command injection vulnerability via the recHour parameter",
        cwe="CWE-78"),

Case(chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2024-57015cstecgi",
        post_binary_filename = "CVE-2024-57020cstecgi1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2024-57020cstecgi\CVE-2024-57020cstecgi.cgi_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2024-57020cstecgi\CVE-2024-57020cstecgi1.cgi_pseudo.c",
        cve_details="TOTOLINK X5000R V9.1.0cu.2350_B20230313 was discovered to contain an OS command injection vulnerability via the hour parameter",
        cwe="CWE-78"),

Case(chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2024-57021cstecgi",
        post_binary_filename = "CVE-2024-57020cstecgi1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2024-57020cstecgi\CVE-2024-57020cstecgi.cgi_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2024-57020cstecgi\CVE-2024-57020cstecgi1.cgi_pseudo.c",
        cve_details="TOTOLINK X5000R V9.1.0cu.2350_B20230313 was discovered to contain an OS command injection vulnerability via the eHour parameter",
        cwe="CWE-78"),

Case(chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2024-57022cstecgi",
        post_binary_filename = "CVE-2024-57020cstecgi1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2024-57020cstecgi\CVE-2024-57020cstecgi.cgi_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2024-57020cstecgi\CVE-2024-57020cstecgi1.cgi_pseudo.c",
        cve_details="TOTOLINK X5000R V9.1.0cu.2350_B20230313 was discovered to contain an OS command injection vulnerability via the sHour parameter",
        cwe="CWE-78"),

    Case(chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2024-57023cstecgi",
        post_binary_filename = "CVE-2024-57020cstecgi1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2024-57020cstecgi\CVE-2024-57020cstecgi.cgi_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2024-57020cstecgi\CVE-2024-57020cstecgi1.cgi_pseudo.c",
        cve_details="TOTOLINK X5000R V9.1.0cu.2350_B20230313 was discovered to contain an OS command injection vulnerability via the week parameter",
        cwe="CWE-78"),



    Case(chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2024-57024cstecgi",
        post_binary_filename = "CVE-2024-57020cstecgi1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2024-57020cstecgi\CVE-2024-57020cstecgi.cgi_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2024-57020cstecgi\CVE-2024-57020cstecgi1.cgi_pseudo.c",
        cve_details="TOTOLINK X5000R V9.1.0cu.2350_B20230313 was discovered to contain an OS command injection vulnerability via the eMinute parameter",
        cwe="CWE-78"),

    Case(chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2024-57025cstecgi",
        post_binary_filename = "CVE-2024-57020cstecgi1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2024-57020cstecgi\CVE-2024-57020cstecgi.cgi_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2024-57020cstecgi\CVE-2024-57020cstecgi1.cgi_pseudo.c",
        cve_details="TOTOLINK X5000R V9.1.0cu.2350_B20230313 was discovered to contain an OS command injection vulnerability via the desc parameter",
        cwe="CWE-78"),


Case(chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2025-5503boa",
        post_binary_filename = "CVE-2025-5502boa1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2025-5502boa\CVE-2025-5502boa_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2025-5502boa\CVE-2025-5502boa1_pseudo.c",
        cve_details="A vulnerability, which was classified as critical, was found in TOTOLINK X15 1.0.0-B20230714.1105. The manipulation of the argument deviceMacAddr leads to stack-based buffer overflow. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.",
        cwe="CWE-787"),

Case(chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2017-13772httpd",
        post_binary_filename = "CVE-2017-13772httpd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2017-13772httpd\CVE-2017-13772httpd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2017-13772httpd\CVE-2017-13772httpd1_pseudo.c",
        cve_details="Multiple stack-based buffer overflows in TP-Link WR940N WiFi routers with hardware version 4 allow remote authenticated users to execute arbitrary code via the (1) ping_addr parameter to PingIframeRpm.htm or (2) dnsserver2 parameter to WanStaticIpV6CfgRpm.htm.",
        cwe="CWE-119"),

    Case(chat_id="paper-3.16",  
        history_root=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history",
        binary_filename="CVE-2017-17020alphapd",
        post_binary_filename = "CVE-2017-17020alphapd1",
        pre_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2017-17020alphapd\CVE-2017-17020alphapd_pseudo.c",
        post_c=r"D:\HUSTCourse\402\chenyi_zhu\VulnAgent-new\VulnAgent\history\paper-3.16\ida\CVE-2017-17020alphapd\CVE-2017-17020alphapd1_pseudo.c",
        cve_details="On D-Link DCS-5009 devices with firmware 1.08.11 and earlier, DCS-5010 devices with firmware 1.14.09 and earlier, and DCS-5020L devices with firmware before 1.15.01, command injection in alphapd (binary responsible for running the camera's web server) allows remote authenticated attackers to execute code through sanitized /setSystemAdmin user input in the AdminID field being passed directly to a call to system.",
        cwe="CWE-78")
]


def _reset_llm_stats() -> None:
    # llm_diff uses agent.llm_stats.LLM_STATS as a shared singleton.
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


def _parse_strategies_env() -> List[int]:
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
        strategies = [s for s in parsed if s in (1, 2, 3, 4)]
        return strategies or [1, 2, 3, 4]

    # Convenience default: if Strategy-3 reuse root is provided as a directory,
    # assume the user only wants to run strategy 3.
    reuse_s3 = os.environ.get("VULN_BATCH_REUSE_STRUCTURED_RESULTS_S3", "").strip()
    if reuse_s3:
        p = Path(reuse_s3)
        if p.exists() and p.is_dir():
            return [3]

    return [1, 2, 3, 4]


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

    strategies = _parse_strategies_env()

    for strategy in strategies:
        _reset_llm_stats()

        # Resume support: if key artifact already exists, skip the run.
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

        # Strategy-3 reuse: allow forcing reuse of an external structured_results JSON (e.g. produced by Strategy 4).
        # Strategy-4 reuse: if Strategy 3 ran (or was previously produced), reuse its structured_results
        # to avoid repeating Scenario/Property + ReAct steps.
        reuse_structured_results: str | None = None
        reuse_s3_dir_mode = False
        if strategy == 3:
            reuse_s3 = os.environ.get("VULN_BATCH_REUSE_STRUCTURED_RESULTS_S3", "").strip()
            if reuse_s3:
                reuse_path = Path(reuse_s3)
                if reuse_path.exists() and reuse_path.is_dir():
                    reuse_s3_dir_mode = True
                    cand1 = reuse_path / case.binary_filename / "structured_results_strategy4.json"
                    cand2 = reuse_path / case.binary_filename / "structured_results.json"
                    if cand1.exists():
                        reuse_structured_results = str(cand1)
                    elif cand2.exists():
                        reuse_structured_results = str(cand2)
                else:
                    reuse_structured_results = reuse_s3
        elif strategy == 4:
            if strategy3_output_dir is not None and strategy3_output_dir.exists():
                reuse_structured_results = str(strategy3_output_dir)
            else:
                cached = case_dir / "structured_results_strategy3.json"
                if cached.exists():
                    reuse_structured_results = str(cached)

        # If Strategy-3 reuse is configured as a directory root, but this case does not
        # have a corresponding Strategy-4 structured_results artifact, skip to avoid
        # accidentally re-running the heavy Scenario/Property/ReAct pipeline.
        if strategy == 3 and reuse_s3_dir_mode and not reuse_structured_results:
            msg = (
                f"[Batch] {case.binary_filename}: strategy 3 skipped "
                f"(missing structured_results in reuse root)."
            )
            print(msg, flush=True)
            _log_line(batch_log, msg)
            manifest["runs"].append(
                {
                    "strategy": 3,
                    "status": "skipped",
                    "reason": "missing_reuse_structured_results",
                }
            )
            continue

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
                except Exception as e:  # noqa: BLE001
                    last_error = f"{type(e).__name__}: {e}"
                    _log_line(batch_log, f"strategy={strategy} attempt={attempt} FAILED: {last_error}")
                    # Small backoff for transient issues (API/network)
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

            # Copy per-strategy artifacts (best-effort, do not crash the whole batch).
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

            # Cache structured_results for Strategy-4 reuse/resume.
            src_struct = output_dir / "structured_results.json"
            if src_struct.exists():
                _copy2(src_struct, case_dir / f"structured_results_strategy{strategy}.json")

            run_entry["status"] = "completed"
            print(f"[Batch] {case.binary_filename}: strategy {strategy} done.", flush=True)
            _log_line(batch_log, f"END strategy={strategy} status=completed missing={len(run_entry['missing_artifacts'])}")

        except Exception as e:  # noqa: BLE001
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
    strategies = _parse_strategies_env()

    out_root_env = os.environ.get("VULN_BATCH_OUT_ROOT", "").strip()
    if out_root_env:
        out_root = Path(out_root_env)
    elif len(strategies) == 1:
        out_root = REPO_ROOT / f"ablation_outputs_strategy{strategies[0]}"
    else:
        out_root = REPO_ROOT / "ablation_outputs"
    out_root.mkdir(parents=True, exist_ok=True)

    cases_to_run: List[Case] = list(CASES)

    # Convenience: when running only Strategy-3 with reuse root directory, limit the
    # batch to binaries that already exist under that directory.
    reuse_s3 = os.environ.get("VULN_BATCH_REUSE_STRUCTURED_RESULTS_S3", "").strip()
    if len(strategies) == 1 and strategies[0] == 3 and reuse_s3:
        reuse_path = Path(reuse_s3)
        if reuse_path.exists() and reuse_path.is_dir():
            existing = {p.name for p in reuse_path.iterdir() if p.is_dir()}
            if existing:
                by_name = {c.binary_filename: c for c in CASES}
                cases_to_run = [by_name[name] for name in sorted(existing) if name in by_name]
                unknown = sorted(existing - set(by_name.keys()))
                if unknown:
                    print(
                        "[Batch] Warning: folders in reuse root not found in CASES (skipped): "
                        + ", ".join(unknown),
                        flush=True,
                    )

    for case in cases_to_run:
        await _run_case(case, out_root=out_root)


if __name__ == "__main__":
    asyncio.run(main())
