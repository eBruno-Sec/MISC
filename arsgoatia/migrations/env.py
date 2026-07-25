"""Alembic environment.

Uses a synchronous psycopg engine (the postgresql+psycopg URL drives both sync
and async) and the ORM metadata as the target. The DB URL comes from Settings so
there is one source of configuration.
"""

from __future__ import annotations

import os
import sys

from alembic import context
from sqlalchemy import create_engine, pool

# packages/ is on sys.path via alembic.ini prepend_sys_path, but be explicit so
# `alembic` invoked from any cwd resolves the shared packages.
_HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..", "packages")))

from config.settings import get_settings  # noqa: E402
from domain.models import Base  # noqa: E402

target_metadata = Base.metadata


def _url() -> str:
    return get_settings().database_url


def run_migrations_offline() -> None:
    context.configure(
        url=_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_url(), poolclass=pool.NullPool, future=True)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
