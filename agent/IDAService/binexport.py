import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional


def _post_json(url: str, payload: Dict[str, Any], timeout_sec: int = 3600) -> Dict[str, Any]:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore") if hasattr(e, "read") else ""
        raise RuntimeError(f"HTTP {e.code} {e.reason}\n{body}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Request failed: {e}") from e

    try:
        return json.loads(raw.decode("utf-8", errors="ignore"))
    except Exception as e:
        raise RuntimeError(f"Response is not JSON.\nraw={raw[:2000]!r}") from e


def cmd_batch(args: argparse.Namespace) -> int:
    payload: Dict[str, Any] = {}

    if args.task_dir:
        payload["task_dir"] = args.task_dir
    if args.modified_dir:
        payload["modified_dir"] = args.modified_dir
    if args.old_dir:
        payload["old_dir"] = args.old_dir
    if args.new_dir:
        payload["new_dir"] = args.new_dir

    payload["ida_version"] = args.ida_version
    payload["copy_to_output_dir"] = 1 if args.copy_to_output_dir else 0
    payload["wait_analysis"] = 1 if args.wait_analysis else 0
    payload["bindiff_output_format"] = args.bindiff_output_format
    payload["reuse_binexport"] = 1 if args.reuse_binexport else 0
    payload["force_reexport"] = 1 if args.force_reexport else 0

    if args.output_dir:
        payload["output_dir"] = args.output_dir
    if args.bindiff_cli:
        payload["bindiff_cli"] = args.bindiff_cli
    if args.old_prefix:
        payload["old_prefix"] = args.old_prefix
    if args.new_prefix:
        payload["new_prefix"] = args.new_prefix

    url = args.host.rstrip("/") + "/batch_bindiff_modified"
    res = _post_json(url, payload, timeout_sec=args.timeout)

    print("=" * 60)
    print("old_dir:", res.get("old_dir"))
    print("new_dir:", res.get("new_dir"))
    print("output_dir:", res.get("output_dir"))
    print("total_pairs:", res.get("total_pairs"))
    print("total_changed_functions_sum:", res.get("total_changed_functions_sum"))
    print("total_similarity_one_functions_sum:", res.get("total_similarity_one_functions_sum"))
    print("summary_path:", res.get("summary_path"))
    print("=" * 60)

    if args.save_json:
        out = Path(args.save_json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
        print("saved:", str(out))

    return 0


def cmd_export(args: argparse.Namespace) -> int:
    payload: Dict[str, Any] = {
        "input_file_path": args.input_file_path,
        "ida_version": args.ida_version,
        "copy_to_output_dir": 1 if args.copy_to_output_dir else 0,
    }
    if args.output_dir:
        payload["output_dir"] = args.output_dir
    if args.cleanup is not None:
        payload["cleanup"] = 1 if args.cleanup else 0

    url = args.host.rstrip("/") + "/export_binexport"
    print("POST", url)
    print("payload:", json.dumps(payload, ensure_ascii=False))
    print("NOTE: /export_binexport returns a zip file stream; this client is for batch use.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Client helper for agent/IDAService/appnew.py (batch BinExport + BinDiff)."
    )
    p.add_argument("--host", default="http://10.12.189.40:5000", help="IDAService host, default: %(default)s")
    p.add_argument("--timeout", type=int, default=3600, help="HTTP timeout seconds, default: %(default)s")

    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("batch", help="Run /batch_bindiff_modified and print summary")
    b.add_argument("--task-dir", default="", help="Task dir containing extracted_diff_files/modified/{old,new}")
    b.add_argument("--modified-dir", default="", help="Dir containing {old,new} subdirs")
    b.add_argument("--old-dir", default="", help="Explicit old dir")
    b.add_argument("--new-dir", default="", help="Explicit new dir")
    b.add_argument("--output-dir", default="", help="Cache/output dir (optional)")
    b.add_argument("--ida-version", default="ida", choices=["ida", "ida64"], help="Default: %(default)s")
    b.add_argument(
        "--wait-analysis",
        action="store_true",
        default=True,
        help="Wait for IDA autoanalysis before exporting BinExport (default: enabled)",
    )
    b.add_argument(
        "--no-wait-analysis",
        dest="wait_analysis",
        action="store_false",
        help="Do not wait for autoanalysis (faster but may reduce export quality)",
    )
    b.add_argument("--bindiff-cli", default="", help="Path to bindiff.exe (optional)")
    b.add_argument(
        "--bindiff-output-format",
        default="log",
        help="BinDiff output format (default: log). Use 'sqlite' if you prefer sqlite results.",
    )
    b.add_argument(
        "--reuse-binexport",
        action="store_true",
        default=True,
        help="Reuse existing .BinExport when meta matches (default: enabled)",
    )
    b.add_argument(
        "--no-reuse-binexport",
        dest="reuse_binexport",
        action="store_false",
        help="Disable reuse and always re-run IDA export",
    )
    b.add_argument(
        "--force-reexport",
        action="store_true",
        default=False,
        help="Delete existing .BinExport/.meta.json before exporting (stronger than --no-reuse-binexport)",
    )
    b.add_argument("--old-prefix", default="old_", help="Default: %(default)s")
    b.add_argument("--new-prefix", default="new_", help="Default: %(default)s")
    b.add_argument(
        "--copy-to-output-dir",
        action="store_true",
        default=True,
        help="Copy binaries into output cache dir before running IDA (default: enabled)",
    )
    b.add_argument(
        "--no-copy-to-output-dir",
        dest="copy_to_output_dir",
        action="store_false",
        help="Do not copy binaries (run IDA in-place)",
    )
    b.add_argument("--save-json", default="", help="Save full JSON response to this path (optional)")
    b.set_defaults(func=cmd_batch)

    e = sub.add_parser("export", help="(Placeholder) Show payload for /export_binexport direct-mode")
    e.add_argument("input_file_path", help="Absolute path to a binary on server filesystem")
    e.add_argument("--output-dir", default="", help="Work dir for IDA outputs (optional)")
    e.add_argument("--ida-version", default="ida", choices=["ida", "ida64"], help="Default: %(default)s")
    e.add_argument(
        "--copy-to-output-dir",
        action="store_true",
        default=True,
        help="Copy binary into output_dir before running IDA (default: enabled)",
    )
    e.add_argument(
        "--no-copy-to-output-dir",
        dest="copy_to_output_dir",
        action="store_false",
        help="Do not copy binary (run IDA in-place)",
    )
    e.add_argument(
        "--cleanup",
        default=None,
        choices=["0", "1"],
        help="Whether to cleanup IDA cache files (0/1). Default: service decides.",
    )
    e.set_defaults(func=cmd_export)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "batch":
        if not (args.task_dir or args.modified_dir or (args.old_dir and args.new_dir)):
            parser.error("batch requires --task-dir or --modified-dir or (--old-dir and --new-dir)")
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
