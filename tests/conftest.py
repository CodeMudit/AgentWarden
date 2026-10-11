"""Shared pytest fixtures."""

import os

# Ensure tests use an in-memory SQLite DB and predictable secrets
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-pytest")
os.environ.setdefault("LEDGER_CHECKPOINT_KEY", "test-ledger-hmac-key")
os.environ.setdefault("DEMO_MODE", "true")

# Clear settings cache so env overrides take effect
from app.config import get_settings

get_settings.cache_clear()
