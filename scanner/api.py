"""
FastAPI application — all HTTP endpoints for the MCP Scanner web app.

Serves:
- Static files (frontend HTML, JS, CSS)
- Auth endpoints (signup, login, logout)
- Scan config CRUD
- Scan run management (start, poll, abort, report)
- Health check
"""

from __future__ import annotations

import json
import uuid
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, Depends, Cookie, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from scanner.db import init_db, get_conn
from scanner.session import SessionManager
from scanner.local_auth import (
    create_local_user,
    authenticate_local_user,
    get_local_user,
)
from scanner.auth import get_customer_id
from scanner.attacks.registry import ATTACK_REGISTRY, get_all_attack_ids
from scanner.logger import log

# ── App Setup ──

# Resolve project root (parent of scanner/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"
STATIC_DIR = PROJECT_ROOT / "static"


@asynccontextmanager
async def lifespan(app):
    """Application lifecycle — runs on startup and shutdown."""
    # ── Startup ──
    try:
        init_db()
        log("db_initialized")
    except Exception as exc:
        log("db_init_error", error=str(exc))

    # Recover scans stuck in running/queued state (worker crash recovery)
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """UPDATE scan_runs SET status = 'failed', error_message = 'Server restarted — scan was interrupted',
               completed_at = NOW()
               WHERE status IN ('running', 'queued')
               AND (started_at IS NULL OR started_at < NOW() - INTERVAL '15 minutes')"""
        )
        recovered = cur.rowcount
        conn.commit()
        cur.close()
        conn.close()
        if recovered:
            log("stale_scans_recovered", count=recovered)
    except Exception as exc:
        log("stale_scan_recovery_error", error=str(exc))

    yield  # App is running
    # ── Shutdown ── (nothing needed for now)


app = FastAPI(title="MCP RedTeam Scanner", version="1.0.0", lifespan=lifespan)

# ── CORS ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("CORS_ORIGIN", "*")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static directories
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ── Cookie Helpers ──

COOKIE_NAME = "session_id"
COOKIE_MAX_AGE = 24 * 3600  # 24 hours


def _set_session_cookie(response: Response, session_id: str):
    """Set HTTP-only session cookie."""
    is_prod = os.getenv("ENV_MODE", "local") == "production"
    response.set_cookie(
        key=COOKIE_NAME,
        value=session_id,
        httponly=True,
        secure=is_prod,
        samesite="lax",
        max_age=COOKIE_MAX_AGE,
        path="/",
    )


def _clear_session_cookie(response: Response):
    """Clear session cookie."""
    response.delete_cookie(key=COOKIE_NAME, path="/")


# ══════════════════════════════════════════════════════════════
# PAGE ROUTES
# ══════════════════════════════════════════════════════════════


@app.get("/", response_class=HTMLResponse)
async def landing_page():
    """Serve the landing page."""
    index_path = FRONTEND_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(404, "Landing page not found")
    return FileResponse(str(index_path), media_type="text/html")


@app.get("/app", response_class=HTMLResponse)
async def dashboard_page(request: Request, session_id: str = Cookie(None)):
    """
    Serve the dashboard.
    If no valid session, set demo mode cookie.
    """
    response = FileResponse(str(FRONTEND_DIR / "app.html"), media_type="text/html")

    if not session_id:
        response.set_cookie("x-demo-mode", "true", httponly=False, path="/", max_age=3600)
    else:
        customer_id = SessionManager.validate_session(session_id, request.client.host)
        if not customer_id:
            response.set_cookie("x-demo-mode", "true", httponly=False, path="/", max_age=3600)

    return response


@app.get("/demo")
async def demo_redirect():
    """Redirect to /app with demo cookie."""
    response = RedirectResponse(url="/app")
    response.set_cookie("x-demo-mode", "true", httponly=False, path="/", max_age=3600)
    return response


# ══════════════════════════════════════════════════════════════
# HEALTH
# ══════════════════════════════════════════════════════════════


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "service": "mcp-redteam-scanner"}


# ══════════════════════════════════════════════════════════════
# AUTH ENDPOINTS
# ══════════════════════════════════════════════════════════════


@app.post("/api/auth/signup")
async def signup(request: Request):
    """Create a new account."""
    body = await request.json()
    email = body.get("email", "")
    password = body.get("password", "")
    full_name = body.get("full_name")

    try:
        customer_id = create_local_user(email, password, full_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    user = get_local_user(customer_id)
    response = JSONResponse({
        "ok": True,
        "customer_id": customer_id,
        "email": user["email"] if user else email,
    })

    log("user_signup", customer_id=customer_id, email=email)
    return response


@app.post("/api/auth/login")
async def login(request: Request):
    """Sign in with email and password."""
    body = await request.json()
    email = body.get("email", "")
    password = body.get("password", "")

    customer_id = authenticate_local_user(email, password)
    if not customer_id:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    session_id = SessionManager.create_session(customer_id, request.client.host)

    user = get_local_user(customer_id)
    response = JSONResponse({
        "ok": True,
        "customer_id": customer_id,
        "email": user["email"] if user else email,
    })
    _set_session_cookie(response, session_id)
    response.delete_cookie("x-demo-mode", path="/")

    log("user_login", customer_id=customer_id)
    return response


@app.post("/api/logout")
async def logout(request: Request, session_id: str = Cookie(None)):
    """Sign out — destroy session."""
    if session_id:
        SessionManager.delete_session(session_id)

    response = JSONResponse({"ok": True})
    _clear_session_cookie(response)
    return response


@app.get("/api/auth/me")
async def get_me(customer_id: str = Depends(get_customer_id)):
    """Get current user info."""
    user = get_local_user(customer_id)
    if not user:
        raise HTTPException(404, "User not found")
    return {
        "customer_id": customer_id,
        "email": user["email"],
        "full_name": user.get("full_name"),
        "created_at": str(user.get("created_at", "")),
    }


@app.get("/api/access-state")
async def access_state(request: Request, session_id: str = Cookie(None)):
    """
    Return current auth state — used by frontend to decide what to show.
    Does NOT require auth (used before login too).
    """
    result = {"authenticated": False, "demo_mode": False, "email": None}

    if session_id:
        customer_id = SessionManager.validate_session(session_id, request.client.host)
        if customer_id:
            result["authenticated"] = True
            user = get_local_user(customer_id)
            if user:
                result["email"] = user["email"]
                result["full_name"] = user.get("full_name")
                result["customer_id"] = customer_id
            return result

    # Check demo cookie
    demo_cookie = request.cookies.get("x-demo-mode")
    if demo_cookie == "true":
        result["demo_mode"] = True

    return result


# ══════════════════════════════════════════════════════════════
# SCAN CONFIG CRUD
# ══════════════════════════════════════════════════════════════


@app.get("/api/configs")
async def list_configs(customer_id: str = Depends(get_customer_id)):
    """List all scan configs for current user."""
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT * FROM scan_configs WHERE customer_id = %s ORDER BY created_at DESC",
            (customer_id,),
        )
        rows = cur.fetchall()
        return {"configs": [dict(r) for r in rows]}
    finally:
        cur.close()
        conn.close()


@app.post("/api/configs")
async def create_config(request: Request, customer_id: str = Depends(get_customer_id)):
    """Create a new scan config."""
    body = await request.json()
    config_id = str(uuid.uuid4())

    config_json = body.get("config", {})
    name = body.get("name", "Untitled Config")

    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO scan_configs (id, customer_id, name, config_json) VALUES (%s, %s, %s, %s)",
            (config_id, customer_id, name, json.dumps(config_json)),
        )
        conn.commit()
        log("config_created", config_id=config_id, customer_id=customer_id)
        return {"ok": True, "config_id": config_id}
    finally:
        cur.close()
        conn.close()


@app.get("/api/configs/{config_id}")
async def get_config(config_id: str, customer_id: str = Depends(get_customer_id)):
    """Get a specific scan config."""
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT * FROM scan_configs WHERE id = %s AND customer_id = %s",
            (config_id, customer_id),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Config not found")
        return dict(row)
    finally:
        cur.close()
        conn.close()


@app.put("/api/configs/{config_id}")
async def update_config(config_id: str, request: Request, customer_id: str = Depends(get_customer_id)):
    """Update an existing scan config."""
    body = await request.json()

    conn = get_conn()
    cur = conn.cursor()
    try:
        # Verify ownership
        cur.execute(
            "SELECT id FROM scan_configs WHERE id = %s AND customer_id = %s",
            (config_id, customer_id),
        )
        if not cur.fetchone():
            raise HTTPException(404, "Config not found")

        updates = {}
        if "name" in body:
            updates["name"] = body["name"]
        if "config" in body:
            updates["config_json"] = json.dumps(body["config"])

        if updates:
            set_parts = [f"{k} = %s" for k in updates]
            vals = list(updates.values()) + [config_id]
            cur.execute(
                f"UPDATE scan_configs SET {', '.join(set_parts)} WHERE id = %s",
                vals,
            )
            conn.commit()

        log("config_updated", config_id=config_id)
        return {"ok": True}
    finally:
        cur.close()
        conn.close()


@app.delete("/api/configs/{config_id}")
async def delete_config(config_id: str, customer_id: str = Depends(get_customer_id)):
    """Delete a scan config."""
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "DELETE FROM scan_configs WHERE id = %s AND customer_id = %s",
            (config_id, customer_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(404, "Config not found")
        conn.commit()
        log("config_deleted", config_id=config_id)
        return {"ok": True}
    finally:
        cur.close()
        conn.close()


# ══════════════════════════════════════════════════════════════
# SCAN RUNS
# ══════════════════════════════════════════════════════════════


@app.post("/api/runs")
async def start_run(request: Request, customer_id: str = Depends(get_customer_id)):
    """
    Start a new scan run.

    Body can be:
    - {"config_id": "..."} — uses saved config
    - {"target_url": "...", "auth_method": "none", "token": "", "attacks": [...]} — ad-hoc
    """
    body = await request.json()
    run_id = str(uuid.uuid4())

    config_id = body.get("config_id")
    target_url = body.get("target_url", "")
    auth_method = body.get("auth_method", "none")
    token = body.get("token", "")
    attacks = body.get("attacks", get_all_attack_ids())

    # If using saved config, load it
    if config_id:
        conn = get_conn()
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT * FROM scan_configs WHERE id = %s AND customer_id = %s",
                (config_id, customer_id),
            )
            config_row = cur.fetchone()
            if not config_row:
                raise HTTPException(404, "Config not found")

            cfg = config_row.get("config_json", {})
            if isinstance(cfg, str):
                cfg = json.loads(cfg)
            
            # Use saved config values
            target = cfg.get("target", {})
            target_url = target.get("sse_url", target_url)
            auth_method = target.get("auth_method", auth_method)
            token = target.get("token", token)
            attacks = cfg.get("enabled_attacks", attacks)
        finally:
            cur.close()
            conn.close()

    if not target_url:
        raise HTTPException(400, "target_url is required")

    # Create run row
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO scan_runs (id, config_id, customer_id, status, target_url, auth_method, attacks_selected)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (run_id, config_id, customer_id, "queued", target_url, auth_method, json.dumps(attacks)),
        )
        conn.commit()
    finally:
        cur.close()
        conn.close()

    # Enqueue background job
    try:
        from scanner.queue import get_queue
        from scanner.jobs import execute_scan_job

        q = get_queue()
        job = q.enqueue(execute_scan_job, run_id, token, job_timeout="10m")

        # Update run with job_id
        conn = get_conn()
        cur = conn.cursor()
        try:
            cur.execute("UPDATE scan_runs SET job_id = %s WHERE id = %s", (job.id, run_id))
            conn.commit()
        finally:
            cur.close()
            conn.close()

        log("run_enqueued", run_id=run_id, job_id=job.id)
    except Exception as exc:
        log("run_queue_error", run_id=run_id, error=str(exc))
        conn = get_conn()
        cur = conn.cursor()
        try:
            cur.execute(
                """
                UPDATE scan_runs
                SET status = 'failed',
                    error_message = %s,
                    completed_at = NOW()
                WHERE id = %s
                """,
                (f"Failed to enqueue scan: {exc}", run_id),
            )
            conn.commit()
        finally:
            cur.close()
            conn.close()
        raise HTTPException(status_code=503, detail="Scan queue is unavailable. Please try again later.")

    return {"ok": True, "run_id": run_id}


@app.get("/api/runs")
async def list_runs(customer_id: str = Depends(get_customer_id)):
    """List scan runs for current user."""
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT id, config_id, status, target_url, attacks_selected, progress,
                   started_at, completed_at, error_message, created_at
            FROM scan_runs
            WHERE customer_id = %s
            ORDER BY created_at DESC
            LIMIT 50
            """,
            (customer_id,),
        )
        rows = cur.fetchall()
        return {"runs": [dict(r) for r in rows]}
    finally:
        cur.close()
        conn.close()


@app.get("/api/runs/{run_id}")
async def get_run(run_id: str, customer_id: str = Depends(get_customer_id)):
    """Get run status and progress."""
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT id, config_id, status, target_url, attacks_selected, progress,
                   started_at, completed_at, error_message, created_at
            FROM scan_runs
            WHERE id = %s AND customer_id = %s
            """,
            (run_id, customer_id),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Run not found")
        return dict(row)
    finally:
        cur.close()
        conn.close()


@app.post("/api/runs/{run_id}/abort")
async def abort_run(run_id: str, customer_id: str = Depends(get_customer_id)):
    """Abort a running scan."""
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT status, job_id FROM scan_runs WHERE id = %s AND customer_id = %s",
            (run_id, customer_id),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Run not found")

        if row["status"] not in ("queued", "running"):
            raise HTTPException(400, f"Cannot abort run with status: {row['status']}")

        cur.execute(
            "UPDATE scan_runs SET status = 'aborted', completed_at = NOW() WHERE id = %s",
            (run_id,),
        )
        conn.commit()

        # Try to cancel the RQ job
        if row.get("job_id"):
            try:
                from scanner.queue import get_queue
                q = get_queue()
                from rq.job import Job
                job = Job.fetch(row["job_id"], connection=q.connection)
                job.cancel()
            except Exception:
                pass

        log("run_aborted", run_id=run_id)
        return {"ok": True}
    finally:
        cur.close()
        conn.close()


@app.get("/api/runs/{run_id}/report")
async def get_report(run_id: str, customer_id: str = Depends(get_customer_id)):
    """Get the full scan report."""
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT report, status FROM scan_runs WHERE id = %s AND customer_id = %s",
            (run_id, customer_id),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Run not found")

        if row["status"] != "completed":
            raise HTTPException(400, f"Report not available. Scan status: {row['status']}")

        report = row.get("report")
        if isinstance(report, str):
            report = json.loads(report)

        return report or {}
    finally:
        cur.close()
        conn.close()


# ══════════════════════════════════════════════════════════════
# DEMO
# ══════════════════════════════════════════════════════════════


@app.get("/api/demo/report")
async def get_demo_report():
    """Get the permanent demo report (from static file or latest DB scan)."""
    # 1. Try static file first (Permanent Demo)
    demo_file = STATIC_DIR / "demo_report.json"
    if demo_file.exists():
        try:
            with open(demo_file, "r") as f:
                return json.load(f)
        except Exception:
            pass

    # 2. Fallback to latest DB scan
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT report FROM scan_runs WHERE status = 'completed' ORDER BY created_at DESC LIMIT 1"
        )
        row = cur.fetchone()
        if row and row.get("report"):
            report = row["report"]
            if isinstance(report, str):
                report = json.loads(report)
            return report
        
        # 3. Final Fallback
        return {
            "target_url": "Sample Target",
            "summary": {"severity_breakdown": {"total": 0, "risk_score": 0, "risk_level": "low"}},
            "attack_results": []
        }
    finally:
        cur.close()
        conn.close()


# ══════════════════════════════════════════════════════════════
# ATTACK METADATA
# ══════════════════════════════════════════════════════════════


@app.get("/api/attacks")
async def list_attacks():
    """Return metadata for all available attack modules (public endpoint)."""
    return {
        "attacks": [
            {
                "id": aid,
                "name": meta["name"],
                "phase": meta["phase"],
                "risk": meta["risk"],
                "owasp": meta["owasp"],
                "description": meta["description"],
            }
            for aid, meta in ATTACK_REGISTRY.items()
        ]
    }
