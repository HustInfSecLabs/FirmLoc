"""initial schema: vuln_tasks, vuln_events, vuln_findings

Revision ID: 7e6e56c975c9
Revises:
Create Date: 2026-03-11 01:41:39.863866

Baseline migration — creates the three core tables from scratch.
For existing SQLite databases this is a no-op (tables already exist via
create_all + _ensure_sqlite_compat_schema); for fresh PostgreSQL databases
this creates the canonical schema.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "7e6e56c975c9"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # vuln_tasks
    op.create_table(
        "vuln_tasks",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("query", sa.Text, nullable=True),
        sa.Column("cve_id", sa.String(64), nullable=True),
        sa.Column("cwe_id", sa.String(64), nullable=True),
        sa.Column("binary_filename", sa.String(255), nullable=True),
        sa.Column("vendor", sa.String(255), nullable=True),
        sa.Column("work_mode", sa.String(50), nullable=True),
        sa.Column("analysis_mode", sa.String(50), nullable=True),
        sa.Column("old_input_path", sa.String(1024), nullable=True),
        sa.Column("new_input_path", sa.String(1024), nullable=True),
        sa.Column("old_input_name", sa.String(255), nullable=True),
        sa.Column("new_input_name", sa.String(255), nullable=True),
        sa.Column("old_input_size", sa.Integer, nullable=True),
        sa.Column("new_input_size", sa.Integer, nullable=True),
        sa.Column("status", sa.String(50), server_default="pending"),
        sa.Column("current_phase", sa.String(50), server_default="init"),
        sa.Column("current_step", sa.String(255), nullable=True),
        sa.Column("progress_percentage", sa.Integer, server_default="0"),
        sa.Column("artifact_dir", sa.String(1024), nullable=True),
        sa.Column("total_files", sa.Integer, server_default="0"),
        sa.Column("uploaded_files", sa.JSON, nullable=True),
        sa.Column("findings_count", sa.Integer, server_default="0"),
        sa.Column("critical_count", sa.Integer, server_default="0"),
        sa.Column("high_count", sa.Integer, server_default="0"),
        sa.Column("medium_count", sa.Integer, server_default="0"),
        sa.Column("low_count", sa.Integer, server_default="0"),
        sa.Column("report_path", sa.String(1024), nullable=True),
        sa.Column("config", sa.JSON, nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("completed_at", sa.DateTime, nullable=True),
    )
    op.create_index("ix_vuln_tasks_status_phase_created_at", "vuln_tasks", ["status", "current_phase", "created_at"])
    op.create_index("ix_vuln_tasks_cve_id", "vuln_tasks", ["cve_id"])
    op.create_index("ix_vuln_tasks_cwe_id", "vuln_tasks", ["cwe_id"])

    # vuln_events
    op.create_table(
        "vuln_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("task_id", sa.String(64), sa.ForeignKey("vuln_tasks.id"), nullable=False),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("phase", sa.String(50), nullable=True),
        sa.Column("title", sa.String(255), nullable=True),
        sa.Column("content", sa.Text, nullable=True),
        sa.Column("data", sa.JSON, nullable=True),
        sa.Column("tool_name", sa.String(100), nullable=True),
        sa.Column("tool_input", sa.JSON, nullable=True),
        sa.Column("tool_output", sa.Text, nullable=True),
        sa.Column("timestamp", sa.DateTime, server_default=sa.func.now()),
        sa.Column("sequence", sa.Integer, server_default="0"),
    )
    op.create_index("ix_vuln_events_task_sequence", "vuln_events", ["task_id", "sequence"])
    op.create_index("ix_vuln_events_task_phase_timestamp", "vuln_events", ["task_id", "phase", "timestamp"])
    op.create_index("ix_vuln_events_event_type", "vuln_events", ["event_type"])

    # vuln_findings
    op.create_table(
        "vuln_findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("task_id", sa.String(64), sa.ForeignKey("vuln_tasks.id"), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("severity", sa.String(50), server_default="medium"),
        sa.Column("status", sa.String(50), server_default="detected"),
        sa.Column("source_stage", sa.String(50), nullable=True),
        sa.Column("binary_name", sa.String(255), nullable=True),
        sa.Column("function_name", sa.String(255), nullable=True),
        sa.Column("file_path", sa.String(1024), nullable=True),
        sa.Column("line_number", sa.Integer, nullable=True),
        sa.Column("old_code", sa.Text, nullable=True),
        sa.Column("new_code", sa.Text, nullable=True),
        sa.Column("diff_summary", sa.Text, nullable=True),
        sa.Column("cwe_id", sa.String(64), nullable=True),
        sa.Column("related_cve", sa.String(64), nullable=True),
        sa.Column("confidence", sa.Float, server_default="0.0"),
        sa.Column("analysis", sa.Text, nullable=True),
        sa.Column("recommendation", sa.Text, nullable=True),
        sa.Column("evidence", sa.JSON, nullable=True),
        sa.Column("reference_items", sa.JSON, nullable=True),
        sa.Column("judgment", sa.JSON, nullable=True),
        sa.Column("extra_data", sa.JSON, nullable=True),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )
    op.create_unique_constraint("uq_vuln_findings_task_binary_function", "vuln_findings", ["task_id", "binary_name", "function_name"])
    op.create_index("ix_vuln_findings_task_status_severity", "vuln_findings", ["task_id", "status", "severity"])
    op.create_index("ix_vuln_findings_cve_cwe", "vuln_findings", ["related_cve", "cwe_id"])
    op.create_index("ix_vuln_findings_function_name", "vuln_findings", ["function_name"])


def downgrade() -> None:
    op.drop_table("vuln_findings")
    op.drop_table("vuln_events")
    op.drop_table("vuln_tasks")
