import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from sqlalchemy import func, select

from .models import (
    VulnEvent,
    VulnEventType,
    VulnFinding,
    VulnFindingSeverity,
    VulnFindingStatus,
    VulnTask,
    VulnTaskPhase,
    VulnTaskStatus,
)
from .session import session_scope


_AGENT_PHASE_MAP = {
    "Intelligence Agent": VulnTaskPhase.INTELLIGENCE.value,
    "Binwalk Agent": VulnTaskPhase.BINWALK.value,
    "Binary Filter Agent": VulnTaskPhase.FILTER.value,
    "IDA Agent": VulnTaskPhase.IDA.value,
    "Bindiff Agent": VulnTaskPhase.BINDIFF.value,
    "Detection Agent": VulnTaskPhase.LLM_ANALYSIS.value,
    "Path Reach Agent": VulnTaskPhase.PATH_REACH.value,
}

_PHASE_PROGRESS_MAP = {
    VulnTaskPhase.INIT.value: 0,
    VulnTaskPhase.UPLOAD.value: 5,
    VulnTaskPhase.INTELLIGENCE.value: 10,
    VulnTaskPhase.BINWALK.value: 25,
    VulnTaskPhase.FILTER.value: 40,
    VulnTaskPhase.IDA.value: 60,
    VulnTaskPhase.BINDIFF.value: 75,
    VulnTaskPhase.LLM_ANALYSIS.value: 85,
    VulnTaskPhase.PATH_REACH.value: 95,
    VulnTaskPhase.REPORT.value: 100,
}

_SEVERITY_ORDER = {
    VulnFindingSeverity.CRITICAL.value: 4,
    VulnFindingSeverity.HIGH.value: 3,
    VulnFindingSeverity.MEDIUM.value: 2,
    VulnFindingSeverity.LOW.value: 1,
    VulnFindingSeverity.INFO.value: 0,
}


def _next_sequence(session, chat_id: str) -> int:
    stmt = select(func.max(VulnEvent.sequence)).where(VulnEvent.task_id == chat_id)
    current = session.scalar(stmt)
    return (current or 0) + 1


def _phase_from_agent(agent: Optional[str]) -> Optional[str]:
    if not agent:
        return None
    return _AGENT_PHASE_MAP.get(agent)


def _coerce_json(value: Any) -> Any:
    if value is None:
        return None
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {key: _coerce_json(val) for key, val in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_coerce_json(item) for item in value]
    return value


def _json_text(value: Any) -> Optional[str]:
    payload = _coerce_json(value)
    if payload is None:
        return None
    if isinstance(payload, str):
        return payload
    try:
        return json.dumps(payload, ensure_ascii=False)
    except TypeError:
        return str(payload)


def _task_name(chat_id: str, query: Optional[str], binary_filename: Optional[str]) -> str:
    if binary_filename:
        return binary_filename
    if query:
        compact = " ".join(query.strip().split())
        return compact[:80] if compact else chat_id
    return chat_id


def _merge_dict(existing: Optional[Dict[str, Any]], updates: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    merged = dict(existing or {})
    merged.update(_coerce_json(updates) or {})
    return merged


def _append_unique_items(existing: Optional[list], items: Iterable[Any]) -> list:
    result = list(existing or [])
    for item in items:
        payload = _coerce_json(item)
        if payload is None or payload in result:
            continue
        result.append(payload)
    return result


def _apply_task_stats(task: VulnTask) -> None:
    findings = list(task.findings or [])
    task.findings_count = len(findings)
    task.critical_count = sum(1 for item in findings if item.severity == VulnFindingSeverity.CRITICAL.value)
    task.high_count = sum(1 for item in findings if item.severity == VulnFindingSeverity.HIGH.value)
    task.medium_count = sum(1 for item in findings if item.severity == VulnFindingSeverity.MEDIUM.value)
    task.low_count = sum(1 for item in findings if item.severity == VulnFindingSeverity.LOW.value)


def _ensure_task_row(
    session,
    chat_id: str,
    query: Optional[str] = None,
    binary_filename: Optional[str] = None,
    artifact_dir: Optional[str] = None,
) -> VulnTask:
    task = session.get(VulnTask, chat_id)
    if task is None:
        task = VulnTask(
            id=chat_id,
            name=_task_name(chat_id, query, binary_filename),
            query=query,
            binary_filename=binary_filename,
            artifact_dir=artifact_dir,
        )
        session.add(task)
        session.flush()
        return task

    if query and not task.query:
        task.query = query
    if binary_filename and not task.binary_filename:
        task.binary_filename = binary_filename
    if artifact_dir:
        task.artifact_dir = artifact_dir
    if not task.name or task.name == chat_id:
        task.name = _task_name(chat_id, task.query, task.binary_filename)
    return task


def _apply_upload_slot(task: VulnTask, payload: Dict[str, Any], upload_role: Optional[str]) -> None:
    role = (upload_role or "").strip().lower()
    filename = payload.get("filename")
    saved_path = payload.get("path")
    size_bytes = payload.get("size")

    if role == "old" or (not role and not task.old_input_path):
        task.old_input_path = saved_path
        task.old_input_name = filename
        task.old_input_size = size_bytes
        return

    if role == "new" or (not role and task.old_input_path and task.old_input_path != saved_path and not task.new_input_path):
        task.new_input_path = saved_path
        task.new_input_name = filename
        task.new_input_size = size_bytes


def _add_reference_items(finding: VulnFinding, cwe_id: Optional[str], related_cve: Optional[str]) -> None:
    refs = list(finding.reference_items or [])
    refs = _append_unique_items(
        refs,
        [
            {"type": "cwe", "id": cwe_id} if cwe_id else None,
            {"type": "cve", "id": related_cve} if related_cve else None,
        ],
    )
    finding.reference_items = refs


def ensure_task(
    chat_id: str,
    query: Optional[str] = None,
    cve_id: Optional[str] = None,
    cwe_id: Optional[str] = None,
    binary_filename: Optional[str] = None,
    vendor: Optional[str] = None,
    work_mode: Optional[str] = None,
    analysis_mode: Optional[str] = None,
    artifact_dir: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None,
) -> None:
    with session_scope() as session:
        task = _ensure_task_row(session, chat_id, query=query, binary_filename=binary_filename, artifact_dir=artifact_dir)
        if query:
            task.query = query
        if cve_id:
            task.cve_id = cve_id
        if cwe_id:
            task.cwe_id = cwe_id
        if binary_filename:
            task.binary_filename = binary_filename
        if vendor:
            task.vendor = vendor
        if work_mode:
            task.work_mode = work_mode
        if analysis_mode:
            task.analysis_mode = analysis_mode
        if config:
            task.config = _merge_dict(task.config, config)
        task.name = _task_name(chat_id, task.query, task.binary_filename)


def start_task(
    chat_id: str,
    query: Optional[str] = None,
    cve_id: Optional[str] = None,
    cwe_id: Optional[str] = None,
    binary_filename: Optional[str] = None,
    vendor: Optional[str] = None,
    work_mode: Optional[str] = None,
    analysis_mode: Optional[str] = None,
    artifact_dir: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None,
) -> None:
    with session_scope() as session:
        task = _ensure_task_row(session, chat_id, query=query, binary_filename=binary_filename, artifact_dir=artifact_dir)
        if query:
            task.query = query
        if cve_id:
            task.cve_id = cve_id
        if cwe_id:
            task.cwe_id = cwe_id
        if binary_filename:
            task.binary_filename = binary_filename
        if vendor:
            task.vendor = vendor
        if work_mode:
            task.work_mode = work_mode
        if analysis_mode:
            task.analysis_mode = analysis_mode
        if artifact_dir:
            task.artifact_dir = artifact_dir
        if config:
            task.config = _merge_dict(task.config, config)
        task.name = _task_name(chat_id, task.query, task.binary_filename)
        # Allow restarting completed/failed tasks — reset terminal state cleanly
        task.status = VulnTaskStatus.RUNNING.value
        task.current_phase = VulnTaskPhase.INIT.value
        task.current_step = "任务已启动"
        task.progress_percentage = _PHASE_PROGRESS_MAP[VulnTaskPhase.INIT.value]
        task.error_message = None
        task.completed_at = None
        if task.started_at is None:
            task.started_at = datetime.utcnow()
        event = VulnEvent(
            id=str(uuid.uuid4()),
            task_id=chat_id,
            event_type=VulnEventType.TASK_STARTED.value,
            phase=VulnTaskPhase.INIT.value,
            title="任务启动",
            content=query,
            data={
                "cve_id": cve_id,
                "cwe_id": cwe_id,
                "binary_filename": binary_filename,
                "vendor": vendor,
                "work_mode": work_mode,
                "analysis_mode": analysis_mode,
            },
            sequence=_next_sequence(session, chat_id),
        )
        session.add(event)


def record_upload(
    chat_id: str,
    filename: str,
    saved_path: str,
    size_bytes: int,
    content_type: Optional[str] = None,
    upload_role: Optional[str] = None,
    artifact_dir: Optional[str] = None,
) -> None:
    with session_scope() as session:
        task = _ensure_task_row(
            session,
            chat_id,
            binary_filename=filename,
            artifact_dir=artifact_dir or str(Path(saved_path).parent),
        )
        uploaded = list(task.uploaded_files or [])
        payload = {
            "filename": filename,
            "path": saved_path,
            "size": size_bytes,
            "content_type": content_type,
            "upload_role": upload_role,
            "uploaded_at": datetime.utcnow().isoformat(),
        }
        uploaded = [item for item in uploaded if item.get("path") != saved_path]
        uploaded.append(payload)
        task.uploaded_files = uploaded
        task.total_files = len(uploaded)
        # Only advance status/phase if the task hasn't started execution yet
        _TERMINAL_OR_ACTIVE = {
            VulnTaskStatus.RUNNING.value,
            VulnTaskStatus.ANALYZING.value,
            VulnTaskStatus.COMPLETED.value,
            VulnTaskStatus.FAILED.value,
        }
        if task.status not in _TERMINAL_OR_ACTIVE:
            task.status = VulnTaskStatus.UPLOADING.value
            task.current_phase = VulnTaskPhase.UPLOAD.value
            task.current_step = f"已上传 {filename}"
            task.progress_percentage = _PHASE_PROGRESS_MAP[VulnTaskPhase.UPLOAD.value]
        _apply_upload_slot(task, payload, upload_role)
        event = VulnEvent(
            id=str(uuid.uuid4()),
            task_id=chat_id,
            event_type=VulnEventType.FILE_UPLOADED.value,
            phase=VulnTaskPhase.UPLOAD.value,
            title="文件上传",
            content=f"{filename} ({size_bytes} bytes)",
            data=payload,
            sequence=_next_sequence(session, chat_id),
        )
        session.add(event)


def create_task(
    chat_id: str,
    query: Optional[str] = None,
    cve_id: Optional[str] = None,
    cwe_id: Optional[str] = None,
    binary_filename: Optional[str] = None,
    vendor: Optional[str] = None,
    work_mode: Optional[str] = None,
    analysis_mode: Optional[str] = None,
    artifact_dir: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None,
) -> dict[str, Any]:
    with session_scope() as session:
        task = _ensure_task_row(session, chat_id, query=query, binary_filename=binary_filename, artifact_dir=artifact_dir)
        if query is not None:
            task.query = query
        if cve_id is not None:
            task.cve_id = cve_id
        if cwe_id is not None:
            task.cwe_id = cwe_id
        if binary_filename is not None:
            task.binary_filename = binary_filename
        if vendor is not None:
            task.vendor = vendor
        if work_mode is not None:
            task.work_mode = work_mode
        if analysis_mode is not None:
            task.analysis_mode = analysis_mode
        if artifact_dir is not None:
            task.artifact_dir = artifact_dir
        if config:
            task.config = _merge_dict(task.config, config)
        task.name = _task_name(chat_id, task.query, task.binary_filename)
        task.status = task.status or VulnTaskStatus.PENDING.value
        task.current_phase = task.current_phase or VulnTaskPhase.INIT.value
        if task.progress_percentage is None:
            task.progress_percentage = _PHASE_PROGRESS_MAP[VulnTaskPhase.INIT.value]
        if not task.current_step:
            task.current_step = "任务已创建"
        session.flush()
        payload = _serialize_task(task)
        payload["events_count"] = session.scalar(select(func.count()).select_from(VulnEvent).where(VulnEvent.task_id == chat_id)) or 0
        payload["findings_count"] = session.scalar(select(func.count()).select_from(VulnFinding).where(VulnFinding.task_id == chat_id)) or 0
        return payload


def record_message(
    chat_id: str,
    content: str,
    message_type: str = "message",
    agent: Optional[str] = None,
    tool: Optional[str] = None,
    tool_status: Optional[Any] = None,
    is_last: bool = False,
) -> None:
    with session_scope() as session:
        task = _ensure_task_row(session, chat_id)
        phase = _phase_from_agent(agent)
        if phase:
            task.current_phase = phase
            task.progress_percentage = _PHASE_PROGRESS_MAP.get(phase, task.progress_percentage or 0)
            if task.status not in {VulnTaskStatus.COMPLETED.value, VulnTaskStatus.FAILED.value}:
                task.status = VulnTaskStatus.ANALYZING.value
        if content and message_type in {"header1", "header2", "message"}:
            compact = content.strip().splitlines()[0][:255]
            if compact:
                task.current_step = compact

        event_type = VulnEventType.PHASE_STARTED.value if message_type == "header1" and phase else VulnEventType.LOG_MESSAGE.value
        event = VulnEvent(
            id=str(uuid.uuid4()),
            task_id=chat_id,
            event_type=event_type,
            phase=phase,
            title=agent or message_type,
            content=content,
            data={
                "message_type": message_type,
                "tool": tool,
                "tool_status": _coerce_json(tool_status),
                "is_last": is_last,
            },
            tool_name=tool,
            tool_input={"message_type": message_type, "is_last": is_last} if tool else None,
            tool_output=_json_text(tool_status) if tool else None,
            sequence=_next_sequence(session, chat_id),
        )
        session.add(event)


def _get_or_create_finding(session, chat_id: str, binary_name: Optional[str], function_name: str) -> VulnFinding:
    stmt = select(VulnFinding).where(
        VulnFinding.task_id == chat_id,
        VulnFinding.binary_name == binary_name,
        VulnFinding.function_name == function_name,
    )
    finding = session.scalar(stmt)
    if finding is None:
        finding = VulnFinding(
            id=str(uuid.uuid4()),
            task_id=chat_id,
            title=f"Potential vulnerability in {function_name}",
            binary_name=binary_name,
            function_name=function_name,
        )
        session.add(finding)
        session.flush()
    return finding


def record_detection_findings(
    chat_id: str,
    binary_name: Optional[str],
    vulnerable_functions: Iterable[str],
    cwe_id: Optional[str] = None,
    related_cve: Optional[str] = None,
) -> None:
    functions = sorted({item for item in vulnerable_functions if item})
    if not functions:
        return

    with session_scope() as session:
        task = _ensure_task_row(session, chat_id, binary_filename=binary_name)
        for function_name in functions:
            finding = _get_or_create_finding(session, chat_id, binary_name, function_name)
            finding.title = f"Potential vulnerability in {function_name}"
            finding.description = "Detection Agent identified this function as potentially vulnerable."
            finding.source_stage = VulnTaskPhase.LLM_ANALYSIS.value
            finding.severity = max(
                finding.severity or VulnFindingSeverity.INFO.value,
                VulnFindingSeverity.MEDIUM.value,
                key=lambda item: _SEVERITY_ORDER.get(item, 0),
            )
            finding.status = VulnFindingStatus.DETECTED.value
            finding.cwe_id = cwe_id or finding.cwe_id
            finding.related_cve = related_cve or finding.related_cve
            finding.confidence = max(finding.confidence or 0.0, 0.6)
            finding.evidence = _merge_dict(
                finding.evidence,
                {
                    "detection": {
                        "binary_name": binary_name,
                        "function_name": function_name,
                        "detected_at": datetime.utcnow().isoformat(),
                    }
                },
            )
            finding.judgment = _merge_dict(
                finding.judgment,
                {
                    "detection": {
                        "status": VulnFindingStatus.DETECTED.value,
                        "confidence": finding.confidence,
                    }
                },
            )
            _add_reference_items(finding, cwe_id, related_cve)
            extra = dict(finding.extra_data or {})
            extra.update({"source": "detection"})
            finding.extra_data = extra

        task.current_phase = VulnTaskPhase.LLM_ANALYSIS.value
        task.progress_percentage = _PHASE_PROGRESS_MAP[VulnTaskPhase.LLM_ANALYSIS.value]
        _apply_task_stats(task)
        event = VulnEvent(
            id=str(uuid.uuid4()),
            task_id=chat_id,
            event_type=VulnEventType.FINDING_DETECTED.value,
            phase=VulnTaskPhase.LLM_ANALYSIS.value,
            title="Detection findings",
            content=f"Detection Agent identified {len(functions)} vulnerable functions",
            data={"binary_name": binary_name, "functions": functions},
            sequence=_next_sequence(session, chat_id),
        )
        session.add(event)


def _severity_from_path_result(result: Dict[str, Any]) -> str:
    risk_level = (result.get("risk_level") or "").lower()
    status = (result.get("status") or "").lower()
    is_vulnerable = bool(result.get("is_vulnerable"))

    if risk_level == "high" or (status == "reachable" and is_vulnerable):
        return VulnFindingSeverity.HIGH.value
    if risk_level == "medium" or status == "reachable":
        return VulnFindingSeverity.MEDIUM.value
    if risk_level == "low" or status == "unreachable":
        return VulnFindingSeverity.LOW.value
    return VulnFindingSeverity.INFO.value


def record_path_reach_findings(
    chat_id: str,
    binary_name: Optional[str],
    results: Dict[str, Any],
    cwe_id: Optional[str] = None,
    related_cve: Optional[str] = None,
) -> None:
    if not results:
        return

    with session_scope() as session:
        task = _ensure_task_row(session, chat_id, binary_filename=binary_name)
        for function_name, raw_result in results.items():
            payload = _coerce_json(raw_result) or {}
            finding = _get_or_create_finding(session, chat_id, binary_name, function_name)
            severity = _severity_from_path_result(payload)
            existing_severity = finding.severity or VulnFindingSeverity.INFO.value
            finding.severity = max(existing_severity, severity, key=lambda item: _SEVERITY_ORDER.get(item, 0))
            finding.status = VulnFindingStatus.CONFIRMED.value if payload.get("is_vulnerable") else finding.status or VulnFindingStatus.DETECTED.value
            finding.source_stage = VulnTaskPhase.PATH_REACH.value
            finding.description = payload.get("analysis_summary") or finding.description
            finding.analysis = payload.get("analysis_summary") or finding.analysis
            finding.recommendation = finding.recommendation or "Review the reachable path and confirm whether the vulnerable code path is externally controllable."
            finding.cwe_id = cwe_id or finding.cwe_id
            finding.related_cve = related_cve or finding.related_cve
            finding.confidence = max(finding.confidence or 0.0, 0.9 if payload.get("is_vulnerable") else 0.75 if payload.get("status") == "reachable" else 0.4)
            finding.evidence = _merge_dict(
                finding.evidence,
                {
                    "path_reach": {
                        "status": payload.get("status"),
                        "risk_level": payload.get("risk_level"),
                        "path_count": payload.get("path_count", 0),
                        "paths": payload.get("paths", []),
                        "llm_results": payload.get("llm_results", []),
                        "summary": payload.get("analysis_summary"),
                    }
                },
            )
            finding.judgment = _merge_dict(
                finding.judgment,
                {
                    "path_reach": {
                        "status": finding.status,
                        "confidence": finding.confidence,
                        "is_vulnerable": bool(payload.get("is_vulnerable")),
                    }
                },
            )
            _add_reference_items(finding, cwe_id, related_cve)
            extra = dict(finding.extra_data or {})
            extra.update(
                {
                    "source": "path_reach",
                    "path_status": payload.get("status"),
                    "risk_level": payload.get("risk_level"),
                    "path_count": payload.get("path_count", 0),
                    "paths": payload.get("paths", []),
                    "llm_results": payload.get("llm_results", []),
                    "vuln_type": payload.get("vuln_type"),
                }
            )
            finding.extra_data = extra

        task.current_phase = VulnTaskPhase.PATH_REACH.value
        task.progress_percentage = _PHASE_PROGRESS_MAP[VulnTaskPhase.PATH_REACH.value]
        _apply_task_stats(task)
        event = VulnEvent(
            id=str(uuid.uuid4()),
            task_id=chat_id,
            event_type=VulnEventType.FINDING_DETECTED.value,
            phase=VulnTaskPhase.PATH_REACH.value,
            title="Path reach findings",
            content=f"Path Reach Agent updated {len(results)} findings",
            data={"binary_name": binary_name, "functions": sorted(results.keys())},
            sequence=_next_sequence(session, chat_id),
        )
        session.add(event)


def mark_task_failed(chat_id: str, error_message: str) -> None:
    with session_scope() as session:
        task = _ensure_task_row(session, chat_id)
        task.status = VulnTaskStatus.FAILED.value
        task.error_message = error_message
        task.completed_at = datetime.utcnow()
        task.current_step = (error_message or "任务失败")[:255]
        event = VulnEvent(
            id=str(uuid.uuid4()),
            task_id=chat_id,
            event_type=VulnEventType.TASK_FAILED.value,
            phase=task.current_phase,
            title="任务失败",
            content=error_message,
            data=None,
            sequence=_next_sequence(session, chat_id),
        )
        session.add(event)


def mark_task_completed(chat_id: str) -> None:
    with session_scope() as session:
        task = _ensure_task_row(session, chat_id)
        task.status = VulnTaskStatus.COMPLETED.value
        task.current_phase = VulnTaskPhase.REPORT.value
        task.current_step = "系统运行完成"
        task.progress_percentage = _PHASE_PROGRESS_MAP[VulnTaskPhase.REPORT.value]
        task.completed_at = datetime.utcnow()
        _apply_task_stats(task)
        event = VulnEvent(
            id=str(uuid.uuid4()),
            task_id=chat_id,
            event_type=VulnEventType.TASK_COMPLETED.value,
            phase=VulnTaskPhase.REPORT.value,
            title="任务完成",
            content="系统运行完成。感谢使用 VulnAgent！",
            data=None,
            sequence=_next_sequence(session, chat_id),
        )
        session.add(event)


def _serialize_task(task: VulnTask) -> dict[str, Any]:
    return {
        "chat_id": task.id,
        "name": task.name,
        "query": task.query,
        "cve_id": task.cve_id,
        "cwe_id": task.cwe_id,
        "binary_filename": task.binary_filename,
        "vendor": task.vendor,
        "work_mode": task.work_mode,
        "analysis_mode": task.analysis_mode,
        "status": task.status,
        "current_phase": task.current_phase,
        "current_step": task.current_step,
        "progress_percentage": task.progress_percentage,
        "artifact_dir": task.artifact_dir,
        "total_files": task.total_files,
        "uploaded_files": _coerce_json(task.uploaded_files) or [],
        "old_input": {
            "path": task.old_input_path,
            "name": task.old_input_name,
            "size": task.old_input_size,
        },
        "new_input": {
            "path": task.new_input_path,
            "name": task.new_input_name,
            "size": task.new_input_size,
        },
        "findings_count": task.findings_count,
        "critical_count": task.critical_count,
        "high_count": task.high_count,
        "medium_count": task.medium_count,
        "low_count": task.low_count,
        "report_path": task.report_path,
        "config": _coerce_json(task.config) or {},
        "error_message": task.error_message,
        "created_at": task.created_at.isoformat() if task.created_at else None,
        "started_at": task.started_at.isoformat() if task.started_at else None,
        "completed_at": task.completed_at.isoformat() if task.completed_at else None,
    }



def _serialize_event(event: VulnEvent) -> dict[str, Any]:
    return {
        "id": event.id,
        "task_id": event.task_id,
        "event_type": event.event_type,
        "phase": event.phase,
        "title": event.title,
        "content": event.content,
        "data": _coerce_json(event.data),
        "tool_name": event.tool_name,
        "tool_input": _coerce_json(event.tool_input),
        "tool_output": event.tool_output,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "sequence": event.sequence,
    }



def _serialize_finding(finding: VulnFinding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "task_id": finding.task_id,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "status": finding.status,
        "source_stage": finding.source_stage,
        "binary_name": finding.binary_name,
        "function_name": finding.function_name,
        "file_path": finding.file_path,
        "line_number": finding.line_number,
        "old_code": finding.old_code,
        "new_code": finding.new_code,
        "diff_summary": finding.diff_summary,
        "cwe_id": finding.cwe_id,
        "related_cve": finding.related_cve,
        "confidence": finding.confidence,
        "analysis": finding.analysis,
        "recommendation": finding.recommendation,
        "evidence": _coerce_json(finding.evidence) or {},
        "reference_items": _coerce_json(finding.reference_items) or [],
        "judgment": _coerce_json(finding.judgment) or {},
        "extra_data": _coerce_json(finding.extra_data) or {},
        "created_at": finding.created_at.isoformat() if finding.created_at else None,
        "updated_at": finding.updated_at.isoformat() if finding.updated_at else None,
    }



def get_task_upload_slots(chat_id: str) -> dict[str, Optional[str]]:
    with session_scope() as session:
        task = session.get(VulnTask, chat_id)
        if task is None:
            return {"old_input_path": None, "new_input_path": None}
        return {
            "old_input_path": task.old_input_path,
            "new_input_path": task.new_input_path,
        }


def get_task_detail(chat_id: str) -> Optional[dict[str, Any]]:
    with session_scope() as session:
        task = session.get(VulnTask, chat_id)
        if task is None:
            return None
        payload = _serialize_task(task)
        payload["events_count"] = session.scalar(select(func.count()).select_from(VulnEvent).where(VulnEvent.task_id == chat_id)) or 0
        payload["findings_count"] = session.scalar(select(func.count()).select_from(VulnFinding).where(VulnFinding.task_id == chat_id)) or 0
        return payload



def list_task_events(chat_id: str, limit: int = 100, offset: int = 0) -> dict[str, Any]:
    with session_scope() as session:
        total = session.scalar(select(func.count()).select_from(VulnEvent).where(VulnEvent.task_id == chat_id)) or 0
        stmt = (
            select(VulnEvent)
            .where(VulnEvent.task_id == chat_id)
            .order_by(VulnEvent.sequence.asc(), VulnEvent.timestamp.asc())
            .offset(offset)
            .limit(limit)
        )
        events = session.scalars(stmt).all()
        return {
            "task_id": chat_id,
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": [_serialize_event(event) for event in events],
        }



def list_task_findings(chat_id: str, limit: int = 100, offset: int = 0) -> dict[str, Any]:
    with session_scope() as session:
        total = session.scalar(select(func.count()).select_from(VulnFinding).where(VulnFinding.task_id == chat_id)) or 0
        stmt = (
            select(VulnFinding)
            .where(VulnFinding.task_id == chat_id)
            .order_by(VulnFinding.updated_at.desc(), VulnFinding.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        findings = session.scalars(stmt).all()
        return {
            "task_id": chat_id,
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": [_serialize_finding(finding) for finding in findings],
        }



def list_tasks() -> list[dict[str, Any]]:
    with session_scope() as session:
        stmt = select(VulnTask).order_by(VulnTask.created_at.desc())
        tasks = session.scalars(stmt).all()
        return [
            {
                "chat_id": task.id,
                "chat_title": task.name or task.id,
                "create_time": task.created_at.isoformat() if task.created_at else None,
                "status": task.status,
                "current_phase": task.current_phase,
                "progress_percentage": task.progress_percentage,
                "binary_filename": task.binary_filename,
                "cve_id": task.cve_id,
                "cwe_id": task.cwe_id,
                "analysis_mode": task.analysis_mode,
                "findings_count": task.findings_count,
                "critical_count": task.critical_count,
                "high_count": task.high_count,
                "medium_count": task.medium_count,
                "low_count": task.low_count,
            }
            for task in tasks
        ]
