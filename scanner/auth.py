"""
FastAPI authentication dependency.

Extracts and validates the customer_id from the session cookie.
Use as a dependency in protected endpoints:

    @app.get("/api/configs")
    def list_configs(customer_id: str = Depends(get_customer_id)):
        ...

Adapted from ARTS redteam/auth.py.
"""

from fastapi import Request, HTTPException, Cookie
from scanner.session import SessionManager
from scanner.logger import log


def get_customer_id(request: Request, session_id: str = Cookie(None)):
    """
    Extract and validate customer ID from session cookie.

    Returns:
        customer_id: Internal customer ID

    Raises:
        HTTPException 401: If session is missing or invalid
    """
    if not session_id:
        raise HTTPException(status_code=401, detail="No session")

    customer_id = SessionManager.validate_session(session_id, request.client.host)
    if not customer_id:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    return customer_id
