"""
Utility belt for MCP Red Team attack modules.

Provides shared helpers:
    - payloads: Categorized attack payload libraries
    - jwt_helpers: JWT token forging and manipulation
    - false_positive_diff: Response diffing to prevent false alerts
"""

from src.utils.payloads import (
    SQLI_PAYLOADS,
    CMD_INJECTION_PAYLOADS,
    PATH_TRAVERSAL_PAYLOADS,
    TYPE_CONFUSION_PAYLOADS,
    PROMPT_INJECTION_PAYLOADS,
)
from src.utils.jwt_helpers import (
    forge_alg_none,
    tamper_role,
    decode_jwt_unsafe,
    forge_with_weak_secret,
)
from src.utils.false_positive_diff import (
    DiffResult,
    compute_response_diff,
    is_significant_diff,
    normalize_response,
)

__all__ = [
    "SQLI_PAYLOADS",
    "CMD_INJECTION_PAYLOADS",
    "PATH_TRAVERSAL_PAYLOADS",
    "TYPE_CONFUSION_PAYLOADS",
    "PROMPT_INJECTION_PAYLOADS",
    "forge_alg_none",
    "tamper_role",
    "decode_jwt_unsafe",
    "forge_with_weak_secret",
    "DiffResult",
    "compute_response_diff",
    "is_significant_diff",
    "normalize_response",
]
