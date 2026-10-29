"""
Structured JSON logger for the MCP Scanner backend.

Every log entry is a single JSON line to stdout — easy to parse,
grep, and ship to log aggregators in production.

Usage:
    from scanner.logger import log
    log("scan_started", run_id="abc", target="http://...")
"""

import logging
import json
import sys

logger = logging.getLogger("scanner")
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(handler)
logger.setLevel(logging.INFO)


def log(event: str, **kwargs):
    """Emit a structured JSON log line."""
    payload = {"event": event, **kwargs}
    logger.info(json.dumps(payload, default=str))
