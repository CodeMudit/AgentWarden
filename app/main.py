"""FastAPI application factory and entrypoint."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app import __version__, ledger
from app.api import actions, agents, approvals, ledger_api, policies, system, users
from app.config import get_settings
from app.db import SessionLocal, check_db_connection, init_db
from app.services.escalation import start_escalation_task, stop_escalation_task


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # Genesis ledger entry
    db = SessionLocal()
    try:
        ledger.ensure_genesis(db)
        db.commit()
    finally:
        db.close()
    start_escalation_task(interval=3.0)
    yield
    stop_escalation_task()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="AI Agent Governance and Human Accountability System",
        lifespan=lifespan,
    )

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "validation_error",
                    "message": str(exc.errors()),
                }
            },
        )

    @app.exception_handler(Exception)
    async def generic_handler(request: Request, exc: Exception):
        if settings.debug:
            raise exc
        return JSONResponse(
            status_code=500,
            content={"error": {"code": "internal_error", "message": "Internal server error"}},
        )

    @app.get("/health")
    def health():
        db_ok = check_db_connection()
        head_seq = None
        if db_ok:
            db = SessionLocal()
            try:
                h = ledger.get_head(db)
                head_seq = h["last_seq"]
            except Exception:
                head_seq = None
            finally:
                db.close()
        status = "ok" if db_ok else "degraded"
        code = 200 if db_ok else 503
        body = {
            "status": status,
            "app": settings.app_name,
            "version": settings.app_version or __version__,
            "db": "ok" if db_ok else "unreachable",
            "ledger_head_seq": head_seq,
        }
        return JSONResponse(content=body, status_code=code)

    # Mount API routers under /v1
    app.include_router(actions.router, prefix="/v1")
    app.include_router(approvals.router, prefix="/v1")
    app.include_router(agents.router, prefix="/v1")
    app.include_router(policies.router, prefix="/v1")
    app.include_router(ledger_api.router, prefix="/v1")
    app.include_router(system.router, prefix="/v1")
    app.include_router(users.router, prefix="/v1")

    return app


app = create_app()
