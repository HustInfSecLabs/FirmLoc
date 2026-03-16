import enum
from datetime import datetime

from sqlalchemy import Column, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from .base import Base


class VulnTaskStatus(str, enum.Enum):
    PENDING = "pending"
    UPLOADING = "uploading"
    RUNNING = "running"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class VulnTaskPhase(str, enum.Enum):
    INIT = "init"
    UPLOAD = "upload"
    INTELLIGENCE = "intelligence"
    BINWALK = "binwalk"
    FILTER = "filter"
    IDA = "ida"
    BINDIFF = "bindiff"
    LLM_ANALYSIS = "llm_analysis"
    PATH_REACH = "path_reach"
    REPORT = "report"


class VulnEventType(str, enum.Enum):
    TASK_STARTED = "task_started"
    TASK_COMPLETED = "task_completed"
    TASK_FAILED = "task_failed"
    PHASE_STARTED = "phase_started"
    FILE_UPLOADED = "file_uploaded"
    FINDING_DETECTED = "finding_detected"
    PROGRESS_UPDATE = "progress_update"
    LOG_MESSAGE = "log_message"
    ERROR = "error"


class VulnFindingSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnFindingStatus(str, enum.Enum):
    DETECTED = "detected"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"


class VulnTask(Base):
    __tablename__ = "vuln_tasks"
    __table_args__ = (
        Index("ix_vuln_tasks_status_phase_created_at", "status", "current_phase", "created_at"),
        Index("ix_vuln_tasks_cve_id", "cve_id"),
        Index("ix_vuln_tasks_cwe_id", "cwe_id"),
    )

    id = Column(String(64), primary_key=True)
    name = Column(String(255), nullable=False)
    query = Column(Text, nullable=True)
    cve_id = Column(String(64), nullable=True)
    cwe_id = Column(String(64), nullable=True)
    binary_filename = Column(String(255), nullable=True)
    vendor = Column(String(255), nullable=True)
    work_mode = Column(String(50), nullable=True)
    analysis_mode = Column(String(50), nullable=True)

    old_input_path = Column(String(1024), nullable=True)
    new_input_path = Column(String(1024), nullable=True)
    old_input_name = Column(String(255), nullable=True)
    new_input_name = Column(String(255), nullable=True)
    old_input_size = Column(Integer, nullable=True)
    new_input_size = Column(Integer, nullable=True)

    status = Column(String(50), default=VulnTaskStatus.PENDING.value)
    current_phase = Column(String(50), default=VulnTaskPhase.INIT.value)
    current_step = Column(String(255), nullable=True)
    progress_percentage = Column(Integer, default=0)

    artifact_dir = Column(String(1024), nullable=True)
    total_files = Column(Integer, default=0)
    uploaded_files = Column(JSON, default=list)

    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)

    report_path = Column(String(1024), nullable=True)
    config = Column(JSON, default=dict)
    error_message = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    events = relationship("VulnEvent", back_populates="task", cascade="all, delete-orphan")
    findings = relationship("VulnFinding", back_populates="task", cascade="all, delete-orphan")


class VulnEvent(Base):
    __tablename__ = "vuln_events"
    __table_args__ = (
        Index("ix_vuln_events_task_sequence", "task_id", "sequence"),
        Index("ix_vuln_events_task_phase_timestamp", "task_id", "phase", "timestamp"),
        Index("ix_vuln_events_event_type", "event_type"),
    )

    id = Column(String(36), primary_key=True)
    task_id = Column(String(64), ForeignKey("vuln_tasks.id"), nullable=False)
    event_type = Column(String(50), nullable=False)
    phase = Column(String(50), nullable=True)
    title = Column(String(255), nullable=True)
    content = Column(Text, nullable=True)
    data = Column(JSON, nullable=True)
    tool_name = Column(String(100), nullable=True)
    tool_input = Column(JSON, nullable=True)
    tool_output = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    sequence = Column(Integer, default=0)

    task = relationship("VulnTask", back_populates="events")


class VulnFinding(Base):
    __tablename__ = "vuln_findings"
    __table_args__ = (
        UniqueConstraint("task_id", "binary_name", "function_name", name="uq_vuln_findings_task_binary_function"),
        Index("ix_vuln_findings_task_status_severity", "task_id", "status", "severity"),
        Index("ix_vuln_findings_cve_cwe", "related_cve", "cwe_id"),
        Index("ix_vuln_findings_function_name", "function_name"),
    )

    id = Column(String(36), primary_key=True)
    task_id = Column(String(64), ForeignKey("vuln_tasks.id"), nullable=False)

    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(50), default=VulnFindingSeverity.MEDIUM.value)
    status = Column(String(50), default=VulnFindingStatus.DETECTED.value)
    source_stage = Column(String(50), nullable=True)

    binary_name = Column(String(255), nullable=True)
    function_name = Column(String(255), nullable=True)
    file_path = Column(String(1024), nullable=True)
    line_number = Column(Integer, nullable=True)

    old_code = Column(Text, nullable=True)
    new_code = Column(Text, nullable=True)
    diff_summary = Column(Text, nullable=True)

    cwe_id = Column(String(64), nullable=True)
    related_cve = Column(String(64), nullable=True)
    confidence = Column(Float, default=0.0)

    analysis = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    evidence = Column(JSON, default=dict)
    reference_items = Column(JSON, default=list)
    judgment = Column(JSON, default=dict)
    extra_data = Column(JSON, default=dict)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    task = relationship("VulnTask", back_populates="findings")
