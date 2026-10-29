"""
PostgreSQL database layer for the MCP Scanner.

Provides connection management and schema initialization.
All tables are created idempotently on startup.

Tables:
    customers       — Tenant registry (one per account)
    local_users     — Email/password credentials (1:1 with customers)
    user_sessions   — HTTP-only cookie sessions (many per customer)
    scan_configs    — Saved scan configurations (many per customer)
    scan_runs       — Scan execution state + results (many per customer)
"""

import os
import psycopg2
from psycopg2.extras import RealDictCursor


def get_conn():
    """Get a new PostgreSQL connection using DATABASE_URL."""
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        raise ValueError("DATABASE_URL is not set")
    return psycopg2.connect(db_url, cursor_factory=RealDictCursor)


def init_db():
    """Create all tables and indexes. Safe to call repeatedly."""
    conn = get_conn()
    cur = conn.cursor()

    # ── customers ──
    cur.execute("""
    CREATE TABLE IF NOT EXISTS customers (
        id TEXT PRIMARY KEY,
        name TEXT,
        auth_type TEXT DEFAULT 'local',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # ── local_users ──
    cur.execute("""
    CREATE TABLE IF NOT EXISTS local_users (
        id TEXT PRIMARY KEY,
        customer_id TEXT UNIQUE NOT NULL,
        email TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # ── user_sessions ──
    cur.execute("""
    CREATE TABLE IF NOT EXISTS user_sessions (
        session_id VARCHAR(128) PRIMARY KEY,
        customer_id TEXT NOT NULL,
        ip_address VARCHAR(45),
        created_at TIMESTAMP DEFAULT NOW(),
        expires_at TIMESTAMP NOT NULL
    );
    """)

    # ── scan_configs ──
    cur.execute("""
    CREATE TABLE IF NOT EXISTS scan_configs (
        id TEXT PRIMARY KEY,
        customer_id TEXT NOT NULL,
        name TEXT,
        config_json JSONB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # ── scan_runs ──
    cur.execute("""
    CREATE TABLE IF NOT EXISTS scan_runs (
        id TEXT PRIMARY KEY,
        config_id TEXT,
        customer_id TEXT NOT NULL,
        job_id TEXT,
        status TEXT DEFAULT 'queued',
        target_url TEXT,
        auth_method TEXT DEFAULT 'none',
        attacks_selected JSONB,
        report JSONB,
        progress JSONB,
        started_at TIMESTAMP,
        completed_at TIMESTAMP,
        error_message TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # ── Indexes ──
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON user_sessions(expires_at);")
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_local_users_email_lower ON local_users(LOWER(email));")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_local_users_customer_id ON local_users(customer_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_configs_customer ON scan_configs(customer_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_runs_customer ON scan_runs(customer_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_runs_status ON scan_runs(status);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_runs_job_id ON scan_runs(job_id);")

    conn.commit()
    cur.close()
    conn.close()
