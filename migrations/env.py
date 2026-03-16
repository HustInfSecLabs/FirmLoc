"""Alembic environment configuration for VulnAgent.

Uses the same database URL resolution as db.session:
  1. VULNAGENT_DATABASE_URL env var
  2. config.ini [DATABASE] url
  3. SQLite fallback (local dev only)
"""

from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import VulnAgent models so autogenerate can detect them
from db.base import Base  # noqa: E402
from db.models import VulnTask, VulnEvent, VulnFinding  # noqa: E402, F401
from db.session import get_database_url  # noqa: E402

target_metadata = Base.metadata

# Override sqlalchemy.url from VulnAgent's unified config
config.set_main_option("sqlalchemy.url", get_database_url())


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,  # SQLite ALTER TABLE support
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,  # SQLite ALTER TABLE support
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
