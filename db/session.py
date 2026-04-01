import os
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from config import config_manager

from .base import Base


_engine = None
_SessionLocal = None

_POSTGRES_SCHEMES = (
    "postgresql://",
    "postgresql+psycopg://",
    "postgresql+psycopg2://",
    "postgresql+pg8000://",
)

_SQLITE_COMPAT_COLUMNS = {
    "vuln_tasks": {
        "owner_id": "VARCHAR(64)",
        "external_task_id": "VARCHAR(64)",
        "source": "VARCHAR(64)",
        "old_input_path": "TEXT",
        "new_input_path": "TEXT",
        "old_input_name": "VARCHAR(255)",
        "new_input_name": "VARCHAR(255)",
        "old_input_size": "INTEGER",
        "new_input_size": "INTEGER",
        "report_path": "TEXT",
    },
    "vuln_events": {
        "tool_name": "VARCHAR(100)",
        "tool_input": "JSON",
        "tool_output": "TEXT",
    },
    "vuln_findings": {
        "source_stage": "VARCHAR(50)",
        "evidence": "JSON",
        "reference_items": "JSON",
        "judgment": "JSON",
    },
}

_SQLITE_COMPAT_INDEXES = (
    "CREATE INDEX IF NOT EXISTS ix_vuln_tasks_status_phase_created_at ON vuln_tasks (status, current_phase, created_at)",
    "CREATE INDEX IF NOT EXISTS ix_vuln_tasks_cve_id ON vuln_tasks (cve_id)",
    "CREATE INDEX IF NOT EXISTS ix_vuln_tasks_cwe_id ON vuln_tasks (cwe_id)",
    "CREATE INDEX IF NOT EXISTS ix_vuln_tasks_owner_created_at ON vuln_tasks (owner_id, created_at)",
    "CREATE INDEX IF NOT EXISTS ix_vuln_tasks_external_task_id ON vuln_tasks (external_task_id)",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_vuln_tasks_source_owner_external ON vuln_tasks (source, owner_id, external_task_id)",
    "CREATE INDEX IF NOT EXISTS ix_vuln_events_task_sequence ON vuln_events (task_id, sequence)",
    "CREATE INDEX IF NOT EXISTS ix_vuln_events_task_phase_timestamp ON vuln_events (task_id, phase, timestamp)",
    "CREATE INDEX IF NOT EXISTS ix_vuln_events_event_type ON vuln_events (event_type)",
    "CREATE INDEX IF NOT EXISTS ix_vuln_findings_task_status_severity ON vuln_findings (task_id, status, severity)",
    "CREATE INDEX IF NOT EXISTS ix_vuln_findings_cve_cwe ON vuln_findings (related_cve, cwe_id)",
    "CREATE INDEX IF NOT EXISTS ix_vuln_findings_function_name ON vuln_findings (function_name)",
)


def _default_postgres_url() -> str:
    return "postgresql+psycopg://postgres:postgres@localhost:5432/vulnagent"


def _default_sqlite_url() -> str:
    result_dir = config_manager.config.get("result.path", "savedir", fallback="history")
    db_path = Path(result_dir).resolve() / "vulnagent.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{db_path}"


def get_database_url() -> str:
    env_url = os.getenv("VULNAGENT_DATABASE_URL", "").strip()
    if env_url:
        return env_url

    if config_manager.config.has_section("DATABASE"):
        configured = config_manager.config.get("DATABASE", "url", fallback="").strip()
        if configured:
            return configured

        use_sqlite_fallback = config_manager.config.getboolean("DATABASE", "use_sqlite_fallback", fallback=True)
        if not use_sqlite_fallback:
            return _default_postgres_url()

    return _default_sqlite_url()


def is_postgres_url(database_url: str) -> bool:
    return database_url.startswith(_POSTGRES_SCHEMES)


def get_engine():
    global _engine
    if _engine is None:
        database_url = get_database_url()
        connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
        _engine = create_engine(database_url, future=True, pool_pre_ping=True, connect_args=connect_args)
    return _engine


def get_session_factory():
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=get_engine(), autoflush=False, autocommit=False, expire_on_commit=False, future=True)
    return _SessionLocal


def _ensure_sqlite_compat_schema(engine) -> None:
    inspector = inspect(engine)
    with engine.begin() as conn:
        for table_name, columns in _SQLITE_COMPAT_COLUMNS.items():
            if not inspector.has_table(table_name):
                continue
            existing = {column["name"] for column in inspector.get_columns(table_name)}
            for column_name, column_type in columns.items():
                if column_name in existing:
                    continue
                conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"))
        for statement in _SQLITE_COMPAT_INDEXES:
            conn.execute(text(statement))


def init_db() -> None:
    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    if str(engine.url).startswith("sqlite"):
        _ensure_sqlite_compat_schema(engine)


@contextmanager
def session_scope():
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
