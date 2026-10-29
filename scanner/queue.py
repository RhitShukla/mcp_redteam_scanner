"""
Redis Queue connection factory.

Usage:
    from scanner.queue import get_queue
    q = get_queue()
    q.enqueue(execute_scan_job, run_id)
"""

import os
from rq import Queue
from redis import Redis


def get_queue() -> Queue:
    """Get the RQ queue connected to Redis."""
    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        raise ValueError("REDIS_URL is not set")

    redis_conn = Redis.from_url(redis_url)
    return Queue("scanner", connection=redis_conn)
