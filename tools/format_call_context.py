#!/usr/bin/env python3
"""CLI helper to format key-parameter data-flow chains from a saved JSON file."""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Iterable

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _load_formatter():
    module_path = PROJECT_ROOT / "agent" / "data_flow_utils.py"
    spec = importlib.util.spec_from_file_location("agent.data_flow_utils", module_path)
    if not spec or not spec.loader:
        raise RuntimeError("Failed to load data_flow_utils module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    return module.format_key_param_data_flow


format_key_param_data_flow = _load_formatter()


def _resolve_path(data: Any, dotted_path: str | None) -> Any:
    if not dotted_path:
        return data
    current = data
    for part in dotted_path.split('.'):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            raise KeyError(f"Path segment '{part}' not found in JSON data")
    return current


def _iter_call_infos(data: Any) -> Iterable[dict]:
    if isinstance(data, dict):
        if "function" in data and ("chains" in data or "data_flow" in data):
            yield data
        for value in data.values():
            yield from _iter_call_infos(value)
    elif isinstance(data, list):
        for item in data:
            yield from _iter_call_infos(item)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Format the key-parameter data-flow chains stored in a JSON file using "
            "the same logic as VulnAgent's RAG prompt builder"
        )
    )
    parser.add_argument("json_file", help="Path to the JSON file returned by the IDA service")
    parser.add_argument(
        "--path",
        help="Optional dotted path to the call-info dict inside the JSON (e.g. result.call_info)",
    )
    parser.add_argument(
        "--index",
        type=int,
        default=0,
        help="When multiple call-info objects are present, pick the Nth (default: 0)",
    )
    args = parser.parse_args()

    json_path = Path(args.json_file)
    if not json_path.is_file():
        parser.error(f"JSON file not found: {json_path}")

    with json_path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)

    try:
        data = _resolve_path(data, args.path)
    except KeyError as exc:
        parser.error(str(exc))

    call_infos = list(_iter_call_infos(data))
    if not call_infos:
        parser.error("No call-info object with chains/data_flow found in the provided JSON")

    idx = args.index
    if idx < 0 or idx >= len(call_infos):
        parser.error(f"index {idx} out of range (found {len(call_infos)} call-info objects)")

    text = format_key_param_data_flow(call_infos[idx])
    if not text:
        print("<empty>")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
