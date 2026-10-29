"""
Scan Runner — 4-phase orchestrator.

Connects to the MCP server, runs Blueprint Analyzer (Phase 0),
then iterates through enabled attack modules in phase order.
Updates the scan_runs row with progress and results in real-time.

This is the core engine that the RQ worker calls.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timezone
from typing import Any, Callable

from scanner.db import get_conn
from scanner.logger import log
from scanner.harness.mcp_client import MCPHarness
from scanner.attacks.registry import (
    get_phases_with_attacks,
    PHASE_LABELS,
    ATTACK_REGISTRY,
)
from scanner.attacks.modules import run_attack
from scanner.scoring.judge import generate_summary


def _update_run(run_id: str, **fields):
    """Update scan_runs row with given fields."""
    if not fields:
        return

    # Whitelist — only these columns can be updated dynamically
    _ALLOWED_COLUMNS = {"status", "report", "progress", "started_at", "completed_at", "error_message", "job_id"}

    conn = get_conn()
    cur = conn.cursor()
    try:
        set_clauses = []
        values = []
        for key, val in fields.items():
            if key not in _ALLOWED_COLUMNS:
                raise ValueError(f"Cannot update column: {key}")
            set_clauses.append(f"{key} = %s")
            if isinstance(val, (dict, list)):
                values.append(json.dumps(val, default=str))
            else:
                values.append(val)
        values.append(run_id)
        cur.execute(
            f"UPDATE scan_runs SET {', '.join(set_clauses)} WHERE id = %s",
            values,
        )
        conn.commit()
    finally:
        cur.close()
        conn.close()


async def execute_scan(run_id: str, config_json: dict) -> dict:
    """
    Execute a full scan.

    Args:
        run_id: Scan run UUID
        config_json: Parsed config from scan_configs.config_json

    Returns:
        Full report dict
    """
    target = config_json.get("target", {})
    sse_url = target.get("sse_url", "")
    auth_method = target.get("auth_method", "none")
    token = target.get("token", "")
    enabled_attacks = config_json.get("enabled_attacks", list(ATTACK_REGISTRY.keys()))
    scan_settings = config_json.get("scan_settings", {})

    log("scan_starting", run_id=run_id, url=sse_url, attacks=len(enabled_attacks))

    # Mark as running
    _update_run(
        run_id,
        status="running",
        started_at=datetime.now(timezone.utc).isoformat(),
        progress={"phase": "connecting", "current_module": None, "modules_done": 0, "modules_total": len(enabled_attacks)},
    )

    harness = MCPHarness()

    try:
        # ── Phase 0: Connect + Blueprint Analysis ──
        _update_run(run_id, progress={
            "phase": "connecting",
            "current_module": "Blueprint Analyzer",
            "modules_done": 0,
            "modules_total": len(enabled_attacks),
        })

        await harness.connect(sse_url, auth_method, token)

        phase0_findings = []
        for f in harness.phase0_findings:
            if hasattr(f, "model_dump"):
                phase0_findings.append(f.model_dump(mode="json"))
            elif isinstance(f, dict):
                phase0_findings.append(f)
            else:
                phase0_findings.append(str(f))

        log("scan_phase0_complete", findings=len(phase0_findings))

        # ── Phase 1–3: Execute attack modules ──
        phases = get_phases_with_attacks(enabled_attacks)
        attack_results = []
        modules_done = 0

        for phase_num, phase_attacks in phases:
            phase_label = PHASE_LABELS.get(phase_num, f"Phase {phase_num}")

            for attack_id in phase_attacks:
                meta = ATTACK_REGISTRY.get(attack_id, {})

                _update_run(run_id, progress={
                    "phase": phase_label,
                    "current_module": f"{attack_id} — {meta.get('name', '')}",
                    "modules_done": modules_done,
                    "modules_total": len(enabled_attacks),
                })

                result = await run_attack(
                    attack_id=attack_id,
                    engine=harness.engine,
                    phase0_context=harness.phase0_context,
                )
                attack_results.append(result)
                modules_done += 1

        # ── Finalize: Score + build report ──
        summary = generate_summary(attack_results, phase0_findings)

        report = {
            "scan_id": run_id,
            "target_url": sse_url,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "phase0_findings": phase0_findings,
            "attack_results": attack_results,
            "discovery": {
                "tools": len(harness.tools),
                "resources": len(harness.resources),
                "prompts": len(harness.prompts),
                "tools_list": harness.tools,
            },
            "traces": [t.model_dump() if hasattr(t, "model_dump") else t for t in harness.traces],
        }

        _update_run(
            run_id,
            status="completed",
            report=report,
            completed_at=datetime.now(timezone.utc).isoformat(),
            progress={
                "phase": "completed",
                "current_module": None,
                "modules_done": modules_done,
                "modules_total": len(enabled_attacks),
            },
        )

        log(
            "scan_completed",
            run_id=run_id,
            total_findings=summary["severity_breakdown"]["total"],
            risk_score=summary["severity_breakdown"]["risk_score"],
        )

        return report

    except Exception as exc:
        error_msg = f"{type(exc).__name__}: {exc}"
        log("scan_failed", run_id=run_id, error=error_msg)

        _update_run(
            run_id,
            status="failed",
            error_message=error_msg,
            completed_at=datetime.now(timezone.utc).isoformat(),
        )
        raise

    finally:
        await harness.disconnect()
