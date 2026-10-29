"""
Environment detection for the MCP Scanner backend.

Usage:
    from scanner.env import is_production
    if is_production():
        # production-only behavior
"""

import os


def is_production() -> bool:
    """True when running in production (Docker/cloud)."""
    return os.getenv("ENV_MODE", "local") == "production"


def is_debug() -> bool:
    """True when DEBUG=true is set."""
    return os.getenv("DEBUG", "false").lower() == "true"
