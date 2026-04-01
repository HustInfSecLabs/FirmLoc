"""add owner-aware platform task fields

Revision ID: 1c4f6d8d3a21
Revises: 7e6e56c975c9
Create Date: 2026-03-22 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "1c4f6d8d3a21"
down_revision: Union[str, Sequence[str], None] = "7e6e56c975c9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(inspector, table_name: str, column_name: str) -> bool:
    return any(column["name"] == column_name for column in inspector.get_columns(table_name))


def _has_index(inspector, table_name: str, index_name: str) -> bool:
    return any(index["name"] == index_name for index in inspector.get_indexes(table_name))


def _has_unique_constraint(inspector, table_name: str, constraint_name: str) -> bool:
    return any(constraint["name"] == constraint_name for constraint in inspector.get_unique_constraints(table_name))


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_column(inspector, "vuln_tasks", "owner_id"):
        op.add_column("vuln_tasks", sa.Column("owner_id", sa.String(length=64), nullable=True))
    if not _has_column(inspector, "vuln_tasks", "external_task_id"):
        op.add_column("vuln_tasks", sa.Column("external_task_id", sa.String(length=64), nullable=True))
    if not _has_column(inspector, "vuln_tasks", "source"):
        op.add_column("vuln_tasks", sa.Column("source", sa.String(length=64), nullable=True))

    inspector = sa.inspect(bind)
    if not _has_index(inspector, "vuln_tasks", "ix_vuln_tasks_owner_created_at"):
        op.create_index("ix_vuln_tasks_owner_created_at", "vuln_tasks", ["owner_id", "created_at"])
    if not _has_index(inspector, "vuln_tasks", "ix_vuln_tasks_external_task_id"):
        op.create_index("ix_vuln_tasks_external_task_id", "vuln_tasks", ["external_task_id"])
    if not _has_unique_constraint(inspector, "vuln_tasks", "uq_vuln_tasks_source_owner_external"):
        op.create_unique_constraint(
            "uq_vuln_tasks_source_owner_external",
            "vuln_tasks",
            ["source", "owner_id", "external_task_id"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if _has_unique_constraint(inspector, "vuln_tasks", "uq_vuln_tasks_source_owner_external"):
        op.drop_constraint("uq_vuln_tasks_source_owner_external", "vuln_tasks", type_="unique")
    if _has_index(inspector, "vuln_tasks", "ix_vuln_tasks_external_task_id"):
        op.drop_index("ix_vuln_tasks_external_task_id", table_name="vuln_tasks")
    if _has_index(inspector, "vuln_tasks", "ix_vuln_tasks_owner_created_at"):
        op.drop_index("ix_vuln_tasks_owner_created_at", table_name="vuln_tasks")

    inspector = sa.inspect(bind)
    if _has_column(inspector, "vuln_tasks", "source"):
        op.drop_column("vuln_tasks", "source")
    if _has_column(inspector, "vuln_tasks", "external_task_id"):
        op.drop_column("vuln_tasks", "external_task_id")
    if _has_column(inspector, "vuln_tasks", "owner_id"):
        op.drop_column("vuln_tasks", "owner_id")
