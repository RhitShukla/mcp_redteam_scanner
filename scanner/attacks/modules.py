"""
Attack modules dispatcher.

Imports and runs the existing attack classes from src/attacks/ without
rewriting them. Each attack module is instantiated with the ProbeEngine
and executed via its run() method.

This is the bridge between the web runner and the CLI attack modules.
"""

from __future__ import annotations

import importlib
import time
from typing import Any

from scanner.attacks.registry import ATTACK_REGISTRY, get_attack_metadata
from scanner.logger import log


async def run_attack(
    attack_id: str,
    engine: Any,
    phase0_context: dict | None = None,
) -> dict:
    """
    Run a single attack module and return standardized results.

    Args:
        attack_id: Attack identifier (e.g., "E1", "A1", "D1")
        engine: ProbeEngine instance (connected)
        phase0_context: Phase 0 context dict from BlueprintAnalyzer

    Returns:
        {
            "attack_id": "E1",
            "name": "Weak Authentication",
            "status": "completed" | "error",
            "findings": [...],
            "finding_count": 3,
            "duration_ms": 1234,
            "error": None | "error message"
        }
    """
    meta = get_attack_metadata(attack_id)
    if not meta:
        return {
            "attack_id": attack_id,
            "name": "Unknown",
            "status": "error",
            "findings": [],
            "finding_count": 0,
            "duration_ms": 0,
            "error": f"Unknown attack ID: {attack_id}",
        }

    module_path = meta["module_path"]
    class_name = meta["class_name"]

    log("attack_starting", attack_id=attack_id, name=meta["name"])
    start = time.monotonic()

    try:
        # Dynamically import the attack module
        mod = importlib.import_module(module_path)
        attack_cls = getattr(mod, class_name)

        # Instantiate the attack — all AttackModule subclasses take (engine,)
        attack_instance = attack_cls(engine)

        # Run the attack
        findings = await attack_instance.run()

        # Serialize findings
        serialized_findings = []
        for f in findings:
            if hasattr(f, "model_dump"):
                serialized_findings.append(f.model_dump(mode="json"))
            elif hasattr(f, "dict"):
                serialized_findings.append(f.dict())
            elif isinstance(f, dict):
                serialized_findings.append(f)
            else:
                serialized_findings.append(str(f))

        duration_ms = int((time.monotonic() - start) * 1000)

        log(
            "attack_completed",
            attack_id=attack_id,
            findings=len(serialized_findings),
            duration_ms=duration_ms,
        )

        return {
            "attack_id": attack_id,
            "name": meta["name"],
            "status": "completed",
            "findings": serialized_findings,
            "finding_count": len(serialized_findings),
            "duration_ms": duration_ms,
            "error": None,
        }

    except Exception as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        error_msg = f"{type(exc).__name__}: {exc}"

        log(
            "attack_error",
            attack_id=attack_id,
            error=error_msg,
            duration_ms=duration_ms,
        )

        return {
            "attack_id": attack_id,
            "name": meta["name"],
            "status": "error",
            "findings": [],
            "finding_count": 0,
            "duration_ms": duration_ms,
            "error": error_msg,
        }
