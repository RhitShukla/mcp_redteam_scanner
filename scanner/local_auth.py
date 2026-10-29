"""
Local email/password authentication.

Handles user registration and login with PBKDF2-SHA256 password hashing.
Each user is mapped 1:1 to a customer tenant.

Adapted from ARTS redteam/local_auth.py.
"""

import os
import uuid
import hmac
import hashlib
from scanner.db import get_conn


def normalize_email(email: str) -> str:
    """Normalize email to lowercase, stripped."""
    return (email or "").strip().lower()


def _password_iterations() -> int:
    """PBKDF2 iteration count — configurable via env."""
    try:
        return int(os.getenv("PASSWORD_PBKDF2_ITERATIONS", "260000"))
    except Exception:
        return 260000


def hash_password(password: str) -> str:
    """Hash a password with PBKDF2-SHA256 + random salt."""
    if not isinstance(password, str) or len(password) < 8:
        raise ValueError("Password must be at least 8 characters")

    salt = os.urandom(16)
    iterations = _password_iterations()
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${derived.hex()}"


def verify_password(password: str, encoded_hash: str) -> bool:
    """Verify a password against a stored hash. Timing-safe."""
    try:
        algo, iterations_raw, salt_hex, expected_hex = (encoded_hash or "").split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iterations_raw)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(expected_hex)
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(candidate, expected)
    except Exception:
        return False


def create_local_user(email: str, password: str, full_name: str | None = None) -> str:
    """
    Register a new user.

    Creates a customer tenant + local_users row.
    Returns the customer_id.
    Raises ValueError if email already exists or is invalid.
    """
    email_norm = normalize_email(email)
    if not email_norm or "@" not in email_norm:
        raise ValueError("Invalid email")

    password_hash = hash_password(password)

    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id FROM local_users WHERE LOWER(email)=LOWER(%s)", (email_norm,))
        existing = cur.fetchone()
        if existing:
            raise ValueError("Email already exists")

        customer_id = str(uuid.uuid4())
        user_id = str(uuid.uuid4())

        # Create tenant
        cur.execute(
            "INSERT INTO customers (id, name, auth_type) VALUES (%s, %s, %s)",
            (customer_id, full_name or email_norm, "local"),
        )

        # Create user
        cur.execute(
            """
            INSERT INTO local_users (id, customer_id, email, password_hash, full_name)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (user_id, customer_id, email_norm, password_hash, full_name),
        )

        conn.commit()
        return customer_id
    finally:
        cur.close()
        conn.close()


def authenticate_local_user(email: str, password: str) -> str | None:
    """
    Verify email + password.

    Returns customer_id on success, None on failure.
    """
    email_norm = normalize_email(email)
    if not email_norm:
        return None

    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT customer_id, password_hash FROM local_users WHERE LOWER(email)=LOWER(%s)",
            (email_norm,),
        )
        row = cur.fetchone()
        if not row:
            return None

        if not verify_password(password or "", row.get("password_hash") or ""):
            return None

        return row.get("customer_id")
    finally:
        cur.close()
        conn.close()


def get_local_user(customer_id: str) -> dict | None:
    """Get user info by customer_id."""
    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT id, customer_id, email, full_name, created_at FROM local_users WHERE customer_id=%s",
            (customer_id,),
        )
        return cur.fetchone()
    finally:
        cur.close()
        conn.close()
