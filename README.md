# MCP RedTeam

An AI red teaming framework for evaluating and testing the safety, robustness, and alignment of AI systems.

## Overview

MCP RedTeam provides tools and methodologies for systematically probing AI models to identify vulnerabilities, biases, and failure modes — enabling teams to build safer and more reliable AI products.

Two lineages live here:

| Lineage | Use when |
|---|---|
| **MCP scanner** (`scripts/mcp/run_scan.py`, `src/attacks/`, `src/probe_engine.py`) | Target speaks the MCP protocol (Model Context Protocol). See [Running a Scan](#running-a-scan) below. |
| **Web/LLM redteam** (`src/redteam/`, `engagements/<target>/`, the three skills) | Target is a web app / REST API with LLM endpoints (chat, SSE). See [Web/LLM engagements](#webllm-engagements) below. |

## Web/LLM engagements

The `src/redteam/` library is target-agnostic and manifest-driven. To run a campaign on a new target:

```bash
# 1. Clone the reference engagement folder
cp -r engagements/orbitshift engagements/<your-target>/

# 2. Edit the manifest — fill in base URL, endpoint paths, JWT format
$EDITOR engagements/<your-target>/manifest.yml

# 3. Drop tokens (one per role/tenant). Naming must match manifest.tokens.
echo "<jwt>" > engagements/<your-target>/token_<role>.txt
# (engagements/*/token_*.txt is .gitignored — never commit live tokens)

# 4. (Optional) Drop a browser HAR to auto-discover endpoints
cp ~/Downloads/target-traffic.har engagements/<your-target>/captures/

# 5. (Optional) Add a custom adapter if the manifest can't express the flow
# Default: src/redteam/targets/<your-target>.py subclassing TargetAdapter
```

Then run a workflow inside a Claude conversation in this repo (skills are
auto-discoverable via `/`-trigger):

```
/har-inventory engagements/<your-target>/captures/*.har
/prompt-exfil engagements/<your-target>
/cross-tenant-canary engagements/<your-target>
```

What you provide vs. what's reusable:

| You provide (per engagement) | Reusable across engagements |
|---|---|
| `engagements/<target>/manifest.yml` (target description) | `src/redteam/core/` (HTTP/SSE/JWT/payloads/leak) |
| `engagements/<target>/token_<role>.txt` (auth) | `src/redteam/target.py` (Manifest + TargetAdapter ABC) |
| `engagements/<target>/captures/*.har` (optional, for endpoint discovery) | Three skills: `/prompt-exfil`, `/cross-tenant-canary`, `/har-inventory` |
| `src/redteam/targets/<target>.py` (optional custom adapter) | All 13 cross-engagement memory entries under `~/.claude/projects/.../memory/` |

The reference engagement at [engagements/orbitshift/](engagements/orbitshift/) is the canonical
example — its `manifest.yml` and the OrbitShift adapter at
[src/redteam/targets/orbitshift.py](src/redteam/targets/orbitshift.py) show the
full shape. Full project conventions, gotchas, and post-engagement checklist
live in [CLAUDE.md](CLAUDE.md) (also auto-loaded into every Claude
conversation in this repo).

## Getting Started

### Prerequisites

- Python 3.10+

### Installation

```bash
# Clone the repo
git clone <repo-url>
cd MCP_MCPRedTeam

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate   # macOS/Linux
# .venv\Scripts\activate    # Windows

# Install dependencies
pip install -e ".[dev]"
```

### Running a Scan

Run the scanner against any MCP server with an SSE endpoint:

```bash
# No auth
python scripts/mcp/run_scan.py http://your-server:port/sse

# With bearer token
python scripts/mcp/run_scan.py http://your-server:port/sse --token YOUR_TOKEN --auth-method bearer_token

# With API key
python scripts/mcp/run_scan.py http://your-server:port/sse --token YOUR_KEY --auth-method api_key

# Browser-based OAuth login
python scripts/mcp/run_scan.py http://your-server:port/sse --browser-auth https://app.skill10x.com/auth

# Browser login with custom callback port
python scripts/mcp/run_scan.py http://your-server:port/sse --browser-auth https://app.skill10x.com/auth --callback-port 9090

# Custom output directory
python scripts/mcp/run_scan.py http://your-server:port/sse --output ./results
```

The scanner will:
1. Connect to the endpoint and discover tools, resources, and prompts
2. Run all attack modules (currently D1 — sensitive data detection)
3. Print findings with severity levels to the terminal
4. Save full results and traces as JSON to `./output/scan_<timestamp>.json`

### Running Tests

```bash
# All tests
pytest tests/ -v

# Unit tests only (no server needed)
pytest tests/test_models.py -v
pytest tests/test_d1_sensitive_data.py -v -k "not Integration"

# Integration tests (starts a mock MCP server automatically)
pytest tests/test_probe_engine.py -v
pytest tests/test_d1_sensitive_data.py -v -k "TestD1Integration"
```

### Testing with the Mock Server

A deliberately vulnerable mock MCP server is included for development:

```bash
# Terminal 1 — start the mock server
python tests/mock_mcp_server.py

# Terminal 2 — scan it
python scripts/mcp/run_scan.py http://127.0.0.1:9999/sse
```

## License

Copyright (c) 2026 MCPAI. All rights reserved.
