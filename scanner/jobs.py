"""
Background job handler for scan execution.

Called by the RQ worker process. Loads config from DB,
runs the scan via runner.execute_scan(), and updates results.

Usage (enqueued from api.py):
    from scanner.queue import get_queue
    from scanner.jobs import execute_scan_job
    q = get_queue()
    job = q.enqueue(execute_scan_job, run_id, job_timeout="10m")
"""

from __future__ import annotations

import asyncio
import json
from scanner.db import get_conn
from scanner.runner import execute_scan
from scanner.logger import log


def execute_scan_job(run_id: str, auth_token: str | None = None):
    """
    RQ job entry point.

    Loads the scan config from DB and delegates to runner.execute_scan().
    This function runs in the worker process (not the API process).
    """
    log("job_starting", run_id=run_id)

    # Load run row
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM scan_runs WHERE id = %s", (run_id,))
        run_row = cur.fetchone()
    finally:
        cur.close()
        conn.close()

    if not run_row:
        log("job_error", run_id=run_id, error="Run not found in database")
        return

    # Load config
    config_id = run_row.get("config_id")
    config_json = {}

    if config_id:
        conn = get_conn()
        cur = conn.cursor()
        try:
            cur.execute("SELECT config_json FROM scan_configs WHERE id = %s", (config_id,))
            config_row = cur.fetchone()
            if config_row:
                cfg = config_row.get("config_json")
                if isinstance(cfg, str):
                    config_json = json.loads(cfg)
                elif isinstance(cfg, dict):
                    config_json = cfg
        finally:
            cur.close()
            conn.close()

    # If no config_id, build config from run row data
    if not config_json:
        attacks_selected = run_row.get("attacks_selected")
        if isinstance(attacks_selected, str):
            attacks_selected = json.loads(attacks_selected)
        config_json = {
            "target": {
                "sse_url": run_row.get("target_url", ""),
                "auth_method": run_row.get("auth_method", "none"),
                "token": run_row.get("auth_token", ""),
            },
            "scan_settings": {"timeout_s": 30, "rate_limit": True},
            "enabled_attacks": attacks_selected or [],
        }

    # Run the scan (async → sync bridge for RQ)
    try:
        if auth_token is not None:
            config_json.setdefault("target", {})["token"] = auth_token
        asyncio.run(execute_scan(run_id, config_json))
        log("job_completed", run_id=run_id)
    except Exception as exc:
        log("job_failed", run_id=run_id, error=str(exc))
        # runner.execute_scan already marks the run as failed in DB
