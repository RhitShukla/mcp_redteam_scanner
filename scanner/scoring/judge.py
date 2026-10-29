"""
Severity scoring and report summary generation.

Takes the raw findings from all attack modules and produces
aggregate KPIs for the dashboard and report views.
"""

from __future__ import annotations

from typing import Any


# Severity weights for risk score calculation
SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0,
}

# Risk score thresholds
RISK_THRESHOLDS = {
    "critical": 80,   # 80–100
    "high": 60,        # 60–79
    "medium": 30,      # 30–59
    "low": 0,          # 0–29
}


def _normalize_severity(sev: Any) -> str:
    """Normalize severity to uppercase string."""
    if hasattr(sev, "value"):
        return str(sev.value).upper()
    return str(sev).upper()


def score_findings(findings: list[dict]) -> dict:
    """
    Score a list of findings and return severity breakdown.

    Returns:
        {
            "total": 12,
            "critical": 2,
            "high": 4,
            "medium": 5,
            "low": 1,
            "info": 0,
            "risk_score": 78,
            "risk_level": "high"
        }
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for finding in findings:
        sev = _normalize_severity(finding.get("severity", "INFO"))
        key = sev.lower()
        if key in counts:
            counts[key] += 1

    total = sum(counts.values())

    # Calculate weighted risk score (0–100)
    if total == 0:
        risk_score = 0
    else:
        weighted_sum = sum(
            counts[k] * SEVERITY_WEIGHTS.get(k.upper(), 0) for k in counts
        )
        max_possible = total * SEVERITY_WEIGHTS["CRITICAL"]
        risk_score = min(100, int((weighted_sum / max_possible) * 100)) if max_possible > 0 else 0

    # Determine risk level
    risk_level = "low"
    for level, threshold in sorted(RISK_THRESHOLDS.items(), key=lambda x: -x[1]):
        if risk_score >= threshold:
            risk_level = level
            break

    return {
        "total": total,
        **counts,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }


def generate_summary(attack_results: list[dict], phase0_findings: list[dict] | None = None) -> dict:
    """
    Generate a complete scan summary from all attack results.

    Args:
        attack_results: List of results from run_attack()
        phase0_findings: Optional BlueprintAnalyzer findings

    Returns:
        {
            "severity_breakdown": {...},
            "modules_summary": [...],
            "owasp_coverage": [...],
            "total_duration_ms": 12345,
            "modules_completed": 13,
            "modules_failed": 0,
        }
    """
    # Collect all findings across all modules
    all_findings = []
    if phase0_findings:
        all_findings.extend(phase0_findings)

    for result in attack_results:
        all_findings.extend(result.get("findings", []))

    # Score all findings
    severity_breakdown = score_findings(all_findings)

    # Module-level summary
    modules_summary = []
    total_duration = 0
    modules_completed = 0
    modules_failed = 0

    for result in attack_results:
        # Calculate max severity for this module
        module_findings = result.get("findings", [])
        max_sev = "PASS"
        if module_findings:
            findings_sevs = [_normalize_severity(f.get("severity", "INFO")) for f in module_findings]
            max_sev = max(findings_sevs, key=lambda s: SEVERITY_WEIGHTS.get(s, 0))
        elif result["status"] == "error":
            max_sev = "ERROR"

        modules_summary.append({
            "attack_id": result["attack_id"],
            "name": result["name"],
            "status": result["status"],
            "finding_count": result["finding_count"],
            "duration_ms": result["duration_ms"],
            "max_severity": max_sev,
            "error": result.get("error"),
        })
        total_duration += result.get("duration_ms", 0)
        if result["status"] == "completed":
            modules_completed += 1
        elif result["status"] == "error":
            modules_failed += 1

    # OWASP coverage
    owasp_hits = set()
    from scanner.attacks.registry import ATTACK_REGISTRY
    for result in attack_results:
        if result.get("finding_count", 0) > 0:
            meta = ATTACK_REGISTRY.get(result["attack_id"], {})
            if meta.get("owasp"):
                owasp_hits.add(meta["owasp"])

    return {
        "severity_breakdown": severity_breakdown,
        "modules_summary": modules_summary,
        "owasp_coverage": sorted(owasp_hits),
        "total_duration_ms": total_duration,
        "modules_completed": modules_completed,
        "modules_failed": modules_failed,
    }
