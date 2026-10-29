from __future__ import annotations

import multiprocessing
import socket
import time

import pytest

from src.models import AuthMethod, TargetConfig, TransportType


SERVER_HOST = "127.0.0.1"


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((SERVER_HOST, 0))
        return int(s.getsockname()[1])


def _run_mock_server(port: int):
    from tests.mock_mcp_server import mcp
    import uvicorn

    uvicorn.run(mcp.sse_app(), host=SERVER_HOST, port=port, log_level="error")


@pytest.fixture(scope="session")
def mock_server_base_url():
    port = _pick_free_port()
    proc = multiprocessing.Process(target=_run_mock_server, args=(port,), daemon=True)
    proc.start()
    time.sleep(2)
    yield f"http://{SERVER_HOST}:{port}"
    proc.terminate()
    proc.join(timeout=5)


@pytest.fixture()
def mock_server_config(mock_server_base_url: str) -> TargetConfig:
    return TargetConfig(
        endpoint_url=f"{mock_server_base_url}/sse",
        transport=TransportType.SSE,
        auth_method=AuthMethod.NONE,
    )

