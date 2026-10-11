"""FastAPI application factory and entrypoint."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app import __version__
from app.config import get_settings
from app.db import check_db_connection, init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: ensure tables exist. Shutdown: nothing special yet."""
    init_db()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="AI Agent Governance and Human Accountability System",
        lifespan=lifespan,
    )

    @app.get("/health")
    def health():
        db_ok = check_db_connection()
        status = "ok" if db_ok else "degraded"
        code = 200 if db_ok else 503
        body = {
            "status": status,
            "app": settings.app_name,
            "version": settings.app_version or __version__,
            "db": "ok" if db_ok else "unreachable",
            "ledger_head_seq": None,  # populated in Phase 1
        }
        return JSONResponse(content=body, status_code=code)

    return app


app = create_app()
