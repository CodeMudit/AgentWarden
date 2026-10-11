"""Database engine and session management."""

from __future__ import annotations

import logging
from collections.abc import Generator

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()

connect_args: dict = {}
if settings.is_sqlite:
    # Required for SQLite + FastAPI multi-thread access
    connect_args = {"check_same_thread": False}

engine = create_engine(
    settings.database_url,
    connect_args=connect_args,
    pool_pre_ping=True,
)

if settings.is_sqlite:

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_conn, connection_record):  # noqa: ARG001
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """SQLAlchemy declarative base."""


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_db_connection() -> bool:
    """Return True if the database is reachable."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


# Columns added after initial create_all — applied on every startup.
# Format: (table, column, SQL type fragment for SQLite / Postgres)
_SCHEMA_PATCHES: list[tuple[str, str, str, str]] = [
    # table, column, sqlite_type, postgres_type
    ("action_requests", "evaluation_trace", "JSON", "JSONB"),
]


def ensure_schema() -> None:
    """Add any columns that create_all cannot (existing DBs). Safe to call repeatedly."""
    insp = inspect(engine)
    dialect = engine.dialect.name
    with engine.begin() as conn:
        for table, column, sqlite_type, pg_type in _SCHEMA_PATCHES:
            if table not in insp.get_table_names():
                continue
            existing = {c["name"] for c in insp.get_columns(table)}
            if column in existing:
                continue
            col_type = sqlite_type if dialect == "sqlite" else pg_type
            sql = f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"
            logger.info("schema patch: %s", sql)
            conn.execute(text(sql))
            # refresh inspector for subsequent patches on same table
            insp = inspect(engine)


def init_db() -> None:
    """Create all tables and apply lightweight schema patches."""
    import app.models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    ensure_schema()
