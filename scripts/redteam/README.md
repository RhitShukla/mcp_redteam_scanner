# scripts/redteam/

Web/LLM red-team scripts. All are target-agnostic — they load an engagement
manifest from `engagements/<target>/` and operate against any target whose
shape the manifest describes. See [`CLAUDE.md`](../../CLAUDE.md) §3 for the
new-engagement workflow.

## What lives here

### Top-level — standalone scripts

| Script | Purpose |
|---|---|
| [`extract_sp.py`](extract_sp.py) | Offline utility. Parses raw SSE / JSON-dump text and pulls out the verbatim `system_prompt` value (state-machine extractor; handles truncated streams). |
| [`p1_probe.py`](p1_probe.py) | Cross-tenant canary probe (IDOR test). Plants a marker-tagged DOCX in tenant A via OrbitShiftAdapter, then issues four file-ID forgery variants from tenant B. Invoked by the `/cross-tenant-canary` skill. |

### [`prompt_exfil/`](prompt_exfil/) — system-prompt exfiltration family

Seven scripts that together form the full prompt-exfiltration campaign
(idea sweep → uncapped drain → per-agent enumeration → full-prompt capture
→ refused-agent retries). See the [folder README](prompt_exfil/README.md)
for the campaign workflow and the naming convention that signals refactor
maturity.

## Invocation

From the repo root:

```bash
# Standalone extract_sp.py (no manifest needed):
python3 scripts/redteam/extract_sp.py /path/to/RAW_*.txt

# Manifest-driven probes:
python3 scripts/redteam/p1_probe.py engagements/orbitshift
python3 scripts/redteam/prompt_exfil/exfil_per_agent_enum.py engagements/orbitshift
```

## Library backing these scripts

All manifest-driven probes import from [`src/redteam/`](../../src/redteam/) —
the shared library that holds the HTTP client, SSE parser, JWT helpers,
exfil payloads, leak-hint scoring, and output helpers. Don't reach inside
these scripts to find that logic; reach into `src.redteam.core.*` instead.
