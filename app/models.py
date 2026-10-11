"""SQLAlchemy models – skeleton for Phase 0.

Full models (User, Agent, Policy, ActionRequest, LedgerEntry, LedgerHead)
are implemented in Phase 1.
"""

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class HealthCheck(Base):
    """Minimal table so create_all / migrations have something to create in Phase 0."""

    __tablename__ = "health_checks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    note: Mapped[str | None] = mapped_column(String(255), nullable=True)
