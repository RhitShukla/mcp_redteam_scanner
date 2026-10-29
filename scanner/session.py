"""
Secure HTTP-only cookie session management.

Sessions are:
- Stored in database with auto-expiry (24 hours)
- Sent via httpOnly cookies (not accessible to JavaScript)
- Protected by SameSite=Lax (CSRF protection)
- Automatically invalidated on logout

Adapted from ARTS redteam/session.py — stripped AWS marketplace sessions.
"""

import secrets
from datetime import datetime, timedelta, timezone
from scanner.db import get_conn
from scanner.logger import log


class SessionManager:
    """Manage secure user sessions with HTTP-only cookies."""

    SESSION_TIMEOUT = 24 * 3600  # 24 hours
    SESSION_TABLE = "user_sessions"

    @staticmethod
    def create_session(customer_id: str, ip_address: str) -> str:
        """Create new session, return session_id."""
        session_id = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=SessionManager.SESSION_TIMEOUT)

        conn = get_conn()
        cur = conn.cursor()

        try:
            cur.execute(
                f"""
                INSERT INTO {SessionManager.SESSION_TABLE}
                (session_id, customer_id, expires_at, ip_address)
                VALUES (%s, %s, %s, %s)
                """,
                (session_id, customer_id, expires_at, ip_address),
            )
            conn.commit()
            log("session_created", customer_id=customer_id)
            return session_id
        finally:
            cur.close()
            conn.close()

    @staticmethod
    def validate_session(session_id: str, ip_address: str) -> str | None:
        """Validate session id, return customer_id or None."""
        import os

        conn = get_conn()
        cur = conn.cursor()

        STRICT_IP_BINDING = os.getenv("SESSION_STRICT_IP", "false").lower() == "true"

        try:
            cur.execute(
                f"""
                SELECT customer_id, ip_address FROM {SessionManager.SESSION_TABLE}
                WHERE session_id = %s
                AND expires_at > NOW()
                """,
                (session_id,),
            )
            row = cur.fetchone()

            if not row:
                return None

            if STRICT_IP_BINDING:
                stored_ip = row["ip_address"]
                if stored_ip != ip_address:
                    log(
                        "session_ip_mismatch",
                        customer_id=row["customer_id"],
                        stored_ip=stored_ip,
                        request_ip=ip_address,
                    )
                    return None

            log("session_validated", customer_id=row["customer_id"])
            return row["customer_id"]
        finally:
            cur.close()
            conn.close()

    @staticmethod
    def delete_session(session_id: str):
        """Delete session (logout)."""
        conn = get_conn()
        cur = conn.cursor()

        try:
            cur.execute(
                f"""
                DELETE FROM {SessionManager.SESSION_TABLE}
                WHERE session_id = %s
                """,
                (session_id,),
            )
            conn.commit()
            log("session_deleted")
        finally:
            cur.close()
            conn.close()

    @staticmethod
    def cleanup_expired_sessions():
        """Remove expired sessions. Run periodically via background task."""
        conn = get_conn()
        cur = conn.cursor()

        try:
            cur.execute(
                f"""
                DELETE FROM {SessionManager.SESSION_TABLE}
                WHERE expires_at < NOW()
                """
            )
            affected = cur.rowcount
            conn.commit()
            log("expired_sessions_cleaned", count=affected)
        finally:
            cur.close()
            conn.close()
