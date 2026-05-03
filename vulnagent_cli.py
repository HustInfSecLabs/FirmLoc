import argparse
import asyncio
import os
import uuid
from pathlib import Path


class _OfflineWebSocket:
    class _State:
        CONNECTED = "connected"
        DISCONNECTED = "disconnected"

    client_state = _State.DISCONNECTED

    async def send_json(self, _payload):
        return None


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m vulnagent_cli",
        description="Run VulnAgent end-to-end in pure backend mode.",
    )
    parser.add_argument("--old-firmware", required=True, help="Path to old firmware image")
    parser.add_argument("--new-firmware", required=True, help="Path to new firmware image")
    parser.add_argument("--cve-id", required=True, help="CVE ID, e.g. CVE-2024-0000")
    parser.add_argument("--binary-filename", default="firmware", help="Target binary name hint")
    parser.add_argument("--vendor", default=None, help="Vendor name")
    parser.add_argument("--workdir", default="runs/default", help="Working directory root")
    parser.add_argument("--chat-id", default=None, help="Reuse a specific chat/task id")
    parser.add_argument(
        "--ida-service-url",
        default=None,
        help="Override IDA service URL for this run",
    )
    return parser


def _validate_file(path: str, label: str) -> str:
    full = os.path.abspath(path)
    if not os.path.isfile(full):
        raise FileNotFoundError(f"{label} not found: {full}")
    return full


def _prepare_workdir(path: str) -> str:
    workdir = os.path.abspath(path)
    os.makedirs(workdir, exist_ok=True)
    return workdir


async def _run(args: argparse.Namespace) -> int:
    try:
        from config import config_manager
        from db import init_db, record_upload, start_task
        from agent.VulAgent import VulnAgent
        from agent.parameter_agent import WorkMode
    except ModuleNotFoundError as exc:
        print(f"Missing dependency: {exc}. Please install project dependencies first (e.g. pip install -r requirements.txt).")
        return 2

    init_db()

    old_path = _validate_file(args.old_firmware, "old firmware")
    new_path = _validate_file(args.new_firmware, "new firmware")
    workdir = _prepare_workdir(args.workdir)

    if args.ida_service_url:
        config_manager.config["IDA_SERVICE"]["service_url"] = args.ida_service_url

    chat_id = args.chat_id or f"cli_{uuid.uuid4().hex[:12]}"
    query = (
        f"CLI firmware diff analysis for {args.cve_id}. "
        f"Compare old={Path(old_path).name} and new={Path(new_path).name}."
    )

    start_task(
        chat_id=chat_id,
        query=query,
        cve_id=args.cve_id,
        binary_filename=args.binary_filename,
        vendor=args.vendor,
        work_mode=WorkMode.REPRODUCTION.value,
        analysis_mode="firmware",
        artifact_dir=os.path.join(workdir, chat_id),
        config={"entry": "vulnagent_cli"},
    )

    record_upload(
        chat_id=chat_id,
        filename=Path(old_path).name,
        saved_path=old_path,
        size_bytes=os.path.getsize(old_path),
        content_type="application/octet-stream",
        upload_role="old",
        artifact_dir=os.path.join(workdir, chat_id),
    )
    record_upload(
        chat_id=chat_id,
        filename=Path(new_path).name,
        saved_path=new_path,
        size_bytes=os.path.getsize(new_path),
        content_type="application/octet-stream",
        upload_role="new",
        artifact_dir=os.path.join(workdir, chat_id),
    )

    agent = VulnAgent(
        chat_id=chat_id,
        user_input=query,
        websocket=_OfflineWebSocket(),
        cve_id=args.cve_id,
        binary_filename=args.binary_filename,
        vendor=args.vendor,
        work_mode=WorkMode.REPRODUCTION.value,
        config_dir=workdir,
        analysis_mode="firmware",
    )

    result = await agent.chat()
    if isinstance(result, str) and result:
        print(result)

    final_report = os.path.join(workdir, chat_id, "final_report.json")
    if os.path.exists(final_report):
        print(f"Final report: {final_report}")
        return 0

    print(f"Run finished, report missing: {final_report}")
    return 1


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    code = asyncio.run(_run(args))
    raise SystemExit(code)


if __name__ == "__main__":
    main()
