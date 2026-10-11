"""FastAPI application factory and entrypoint."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

from app import __version__, ledger
from app.api import actions, agents, approvals, ledger_api, policies, system, users
from app.config import get_settings
from app.db import SessionLocal, check_db_connection, init_db
from app.logging_config import setup_logging
from app.security import RedirectToLogin, assert_safe_secrets
from app.services.escalation import start_escalation_task, stop_escalation_task
from app.web import routes as web_routes


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # CSP compatible with Tailwind/Alpine/HTMX/Chart.js CDNs
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com "
            "https://cdn.jsdelivr.net https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'"
        )
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
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
    setup_logging(debug=settings.debug)
    assert_safe_secrets()
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="AI Agent Governance and Human Accountability System",
        lifespan=lifespan,
    )
    app.add_middleware(SecurityHeadersMiddleware)

    templates = Jinja2Templates(directory=str(Path(__file__).parent / "web" / "templates"))

    @app.exception_handler(RedirectToLogin)
    async def redirect_login(request: Request, exc: RedirectToLogin):
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        if request.url.path.startswith("/v1"):
            return JSONResponse(
                status_code=422,
                content={"error": {"code": "validation_error", "message": str(exc.errors())}},
            )
        return JSONResponse(
            status_code=422,
            content={"error": {"code": "validation_error", "message": str(exc.errors())}},
        )

    @app.exception_handler(Exception)
    async def generic_handler(request: Request, exc: Exception):
        if settings.debug:
            raise exc
        if request.url.path.startswith("/v1"):
            return JSONResponse(
                status_code=500,
                content={"error": {"code": "internal_error", "message": "Internal server error"}},
            )
        return templates.TemplateResponse(
            request,
            "500.html",
            {
                "request": request,
                "current_user": None,
                "csrf_token": "",
                "app_version": settings.app_version,
            },
            status_code=500,
        )

    @app.exception_handler(404)
    async def not_found(request: Request, exc):
        if request.url.path.startswith("/v1"):
            return JSONResponse(
                status_code=404,
                content={"error": {"code": "not_found", "message": "Not found"}},
            )
        return templates.TemplateResponse(
            request,
            "404.html",
            {
                "request": request,
                "current_user": None,
                "csrf_token": "",
                "app_version": settings.app_version,
            },
            status_code=404,
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

    # Static
    static_dir = Path(__file__).parent / "web" / "static"
    static_dir.mkdir(exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # API
    app.include_router(actions.router, prefix="/v1")
    app.include_router(approvals.router, prefix="/v1")
    app.include_router(agents.router, prefix="/v1")
    app.include_router(policies.router, prefix="/v1")
    app.include_router(ledger_api.router, prefix="/v1")
    app.include_router(system.router, prefix="/v1")
    app.include_router(users.router, prefix="/v1")

    # Web UI
    app.include_router(web_routes.router)

    return app


app = create_app()
