# scripts/

Project-wide CLI entry points. Three buckets:

| Folder | What it holds | When to use |
|---|---|---|
| [`mcp/`](mcp/) | MCP attack-lineage CLIs (`run_scan.py`, `audit_scan.py`, `verify_remediations.py`) | Targeting an MCP server (e.g. Generic). See top-level [`README.md`](../README.md) "Running a Scan". |
| [`redteam/`](redteam/) | Web/LLM red-team scripts (system-prompt exfil, cross-tenant canary, parsing utilities) | Targeting a web/REST/SSE LLM app. See [`redteam/README.md`](redteam/README.md). |
| [`utils/`](utils/) | Generic helpers (`get_token.py`, `md_to_docx.py`) | Cross-cutting; reused by both lineages. |

## Invocation

All scripts are also `runnable` as modules when invoked from the repo root,
which is the recommended pattern because it lets the scripts import from
`src/redteam/`:

```bash
# Module form (recommended):
python3 -m scripts.mcp.run_scan http://your-server/sse
python3 -m scripts.redteam.p1_probe engagements/orbitshift

# Direct form (also works from repo root, since Python adds CWD to sys.path):
python3 scripts/mcp/run_scan.py http://your-server/sse
```

Engagement-specific scripts live under [`engagements/<target>/scripts/`](../engagements/), NOT here.
That keeps each engagement folder a self-contained kit and ensures the
generic `scripts/` tree never accumulates target-specific clutter.
