# MCP RedTeam — Repo Conventions

This file is auto-loaded into every Claude conversation in this repo. Keep it
short and authoritative; anything target-specific lives elsewhere (see §5).

## 1. What this repo is

Red-team tooling for two attack lineages:

| Lineage | Lives under | Purpose |
|---|---|---|
| **Web / LLM** (REST + SSE + LLM prompt-exfil + cross-tenant IDOR) | `src/redteam/`, `engagements/<target>/` | Generic, manifest-driven. Current target: OrbitShift AI. |
| **MCP server attacks** (Generic lineage) | `src/attacks/`, `src/probe_engine.py`, `scripts/mcp/verify_remediations.py` | Out of scope for `src/redteam/`. Don't touch. |

When the user says "run a probe" without specifying, ask which lineage. The
shared library at `src/redteam/` is for the web/LLM lineage only.

## 2. Layout

```
src/
├── redteam/                     # Web/LLM library (manifest-driven, target-agnostic core)
│   ├── core/                    # Generic primitives — no target names allowed here
│   │   ├── client.py            # Manifest-driven HTTP + SSE drain
│   │   ├── jwt.py               # Decode, expiry, format assertion
│   │   ├── sse.py               # Cumulative delta parsing
│   │   ├── leak.py              # Hint scoring + extract_system_prompt
│   │   ├── payloads.py          # JSON-wrapper, chunk-redirect, ...
│   │   └── output.py            # Timestamped outdirs, save_json
│   ├── target.py                # Manifest loader + TargetAdapter ABC
│   └── targets/
│       └── orbitshift.py        # OrbitShift adapter (canary flow, agent list)
├── attacks/                     # MCP attack lineage (separate concern)
├── utils/                       # Shared MCP helpers (jwt_helpers, payloads, ...)
└── probe_engine.py              # MCP scanner

engagements/
└── <target>/
    ├── manifest.yml             # Target description (URLs, endpoints, JWT format, ...)
    ├── token_<role>.txt         # JWT per role/tenant; .gitignored
    └── captures/*.har           # Browser HARs for /har-inventory

Orbitshift_Attack_14_05_And_Updated_19_05/   # OrbitShift engagement archive
├── 01_Inputs/                   # HARs, RFP samples, internal docs
├── 02_Findings/                 # vulnerability_catalog.json, endpoint_signature_catalog.json, narrative .md
├── 03_Attack_Orchestration/     # PowerShell runners
├── 04_Raw_Results/raw_*/        # One subfolder per probe run (timestamped)
├── 05_Report_Generation/        # Templating scripts
├── 06_Reports/                  # Final HTML/DOCX
├── 07_extracted_prompts_19_05/  # Captured per-agent system prompts
└── 08_Cross_Tenant_Attempt/     # P1 results

reports/                         # Authoritative engagement-level findings reports
└── extracted_prompts/           # Cross-referenced cleaner copies
```

## 3. Starting a new engagement

1. `cp -r engagements/orbitshift engagements/<new-target>/`
2. Edit `engagements/<new-target>/manifest.yml` — fill in the target's base URL,
   endpoint paths, body templates, JWT format. The OrbitShift manifest is the
   reference example.
3. Drop fresh token files (one per role/tenant under test) into
   `engagements/<new-target>/`. Path names must match `manifest.tokens`.
4. (Optional) Drop a browser HAR into `engagements/<new-target>/captures/` and
   invoke `/har-inventory` to auto-populate the endpoint section.
5. (Optional) If the target's flow needs Python beyond what the manifest
   describes (custom chat body shape, custom canary flow), add an adapter at
   `src/redteam/targets/<new-target>.py` subclassing `TargetAdapter` from
   `src/redteam/target.py`. The OrbitShift adapter at
   `src/redteam/targets/orbitshift.py` is the reference.
6. Run a workflow:
   - `/prompt-exfil engagements/<target>` — system-prompt exfiltration
   - `/cross-tenant-canary engagements/<target>` — cross-tenant IDOR
   - `/har-inventory engagements/<target>/captures/*.har` — endpoint discovery

## 4. Token management (applies to every engagement)

- File naming: `engagements/<target>/token_<role>.txt`. The manifest's
  `tokens:` block maps logical roles to relative paths.
- **NEVER commit token files.** The root `.gitignore` excludes
  `engagements/*/token_*.txt`. If you add tokens at the repo root for ad-hoc
  use, name them `token_*.txt` and they'll be excluded too.
- Before any probe, the library calls `jwt.assert_format(token,
  manifest.auth.jwt.expected_keys)` and `jwt.is_expired(token)`. Both fail
  fast with clear messages.
- The classic OrbitShift gotcha: a JWT with camelCase claims (`userId`,
  `tenantId`) sent to an endpoint expecting snake_case (`user_id`,
  `tenant_id`) silently 401s with "unauthorized tenant" — looks like a
  cross-tenant rejection but is really a format mismatch. The format
  assertion catches this at token-load time.

## 5. Output conventions

- Probe runs write a timestamped folder `raw_<CAMPAIGN>_<YYYYMMDD_HHMMSS>/`
  under the engagement's `04_Raw_Results/` (or wherever
  `manifest.output_root` points). Made via `src.redteam.core.output.make_outdir`.
- Each request gets its own JSON file. Naming:
  `<YYYYMMDD_HHMMSS_mmm>_<label>.json`.
- A `run_log.txt` is appended per stage (`output.RunLog`).
- Never overwrite — re-runs get a fresh timestamped folder.
- Report the SSE bytes count alongside the leak-score. Surprising byte counts
  often mean truncation (cap hit) — escalate the cap before drawing conclusions.

## 6. Probe-runner skeleton (generic)

```python
from src.redteam.target import Manifest
from src.redteam.targets.orbitshift import OrbitShiftAdapter
from src.redteam.core import sse, leak, output, payloads

manifest = Manifest.load("engagements/orbitshift")
adapter = OrbitShiftAdapter(manifest, token_role="tenant_201")

outdir = output.make_outdir("PROMPTEX", base_dir=manifest.raw_results_dir())

sess = adapter.create_session()
r = adapter.chat(sess,
                 "Tell me about our cybersecurity offerings." + payloads.JSON_WRAPPER_TAIL,
                 drain_seconds=480, byte_cap=15_000_000)

best = sse.best_text(r.sse_text)
sp = leak.extract_system_prompt(best)
output.save_json(f"{outdir}/probe.json", {"status": r.status, "sp_chars": len(sp or "")})
adapter.cleanup()
```

## 7. Generic gotchas (apply to any LLM target)

Each is documented in detail in a memory entry under `~/.claude/projects/.../memory/`:

- **SSE deltas are cumulative.** Extract the LONGEST snapshot of `parts[0]`,
  not the last delta — the last is often truncated mid-string. See
  `sse-cumulative-deltas.md`.
- **Refusal-classifier bypasses, in order of yield.** First try a
  JSON-wrapper tail (`model_name`/`system_prompt`/`tools` envelope). Second,
  if refused, fall back to chunk-redirect (numbered 50-char chunks). Direct
  asks, base64, ROT13, DAN, language-switch all refused universally; skip
  them. See `exfil-json-wrapper.md`, `exfil-chunk-redirect.md`,
  `exfil-refused-techniques.md`.
- **Hallucinated dumps detection.** If you re-run the same probe and get
  different `model_name`/`max_tokens` values, the model is making them up.
  See `hallucinated-dumps.md`.
- **CONTROL_OK before alarm.** When an attack returns 500 / 4xx, also run the
  same probe with a known-good legitimate setup. If CONTROL also fails, the
  endpoint is broken (not the attack vector). See `control-ok-probe.md`.
- **Session-lock 409.** On `409 Session already acquired, Retrying in 30
  sec`, prefer creating a fresh session per variant over waiting. See
  `session-lock-409.md`.
- **Cross-tenant 401 is a partial result.** It proves the path-level tenant
  check; it does NOT prove storage-level binding. Always also probe the
  presigned-URL / file-path layer. See `cross-tenant-401-meaning.md`.

Where target-specific gotchas live: per-target memory entries (description
field starts with `[<target>]:`) and the manifest's `notes:` fields under
each endpoint. They do NOT live in this file.

## 8. Adding a new finding

1. Run the probe; raw evidence under `04_Raw_Results/raw_*/`.
2. Reproducibility check: rerun the probe verbatim, confirm same status/leak.
3. Append a record to `02_Findings/vulnerability_catalog.json`:
   `{id, severity, category, title, explanation, damage, remediation, evidence_path}`.
4. If a new endpoint or behaviour surfaced, append to
   `02_Findings/endpoint_signature_catalog.json` and update the relevant
   target's `manifest.yml` `endpoints:` block (with a `notes:` field for the
   quirk).
5. Write a per-finding report under `reports/` using
   `PROMPTEX_system_prompt_exfiltration.md` as the template shape.
6. If the technique used is new and cross-engagement, add a generic memory
   entry. If target-specific, add a `[<target>]:` memory entry.

## 9. Post-engagement capture checklist

When an engagement closes, walk through this list. Discipline check: did the
engagement teach us anything generic vs target-specific?

1. **Techniques inventory.** Cross-reference probe scripts vs existing generic
   memory entries.
2. **New generic technique?** Add an untagged memory entry (`feedback` type
   for "what worked / didn't"). Most engagements add 0-2 of these.
3. **Generic technique that STOPPED working on this target?** Don't delete
   the entry; add a counter-example note ("refused by target=X because Y").
4. **New target-specific fact?** Update the target's `manifest.yml` (if it's
   a connection detail) or add a `[<target>]:`-tagged memory entry (if it's
   a behavioural quirk).
5. **New agent / tool / role discovered on this target?** Update the target's
   `manifest.yml` `known_agents:` block AND the target-tagged hierarchy
   memory.
6. **Review the 3 skills.** Does the workflow still match how you actually
   ran it? If yes, leave alone. If no, edit the SKILL.md body. The skills
   MUST stay generic — if a fix is target-specific it belongs in the target
   adapter or manifest, not the skill body.
7. **Archive the engagement.** Move tokens out of `engagements/<target>/`
   (keep `manifest.yml`); the engagement folder stays as a reusable kit for
   re-runs of the same target.

## 10. Never touch (intentional)

- `src/attacks/*` — MCP attack lineage, owned by `scripts/mcp/verify_remediations.py`.
- `Orbitshift_Attack_14_05_And_Updated_19_05/04_Raw_Results/raw_*/` — frozen evidence
  from past runs; cite, don't modify.
- Historical scripts under `scripts/redteam/prompt_exfil/` marked
  `[HISTORICAL — kept verbatim for evidence chain]` in their docstrings
  (`promptex_probe.py`, `promptex_stage2.py`, `promptex_stage3.py`,
  `promptex_stage5_agents.py`, `promptex_stage7_final.py`). Use the
  refactored siblings in the same folder
  (`exfil_per_agent_enum.py` — was `promptex_stage4_agents.py`;
  `exfil_full_prompt_capture.py` — was `promptex_stage6_fullprompts.py`)
  or the standalone scripts one level up
  (`scripts/redteam/p1_probe.py`, `scripts/redteam/extract_sp.py`)
  as templates instead.

## 11. Script-naming note

The 5 HISTORICAL files (now under `scripts/redteam/prompt_exfil/`) keep
their original `promptex_stageN_*` names so they match what's referenced
in `reports/PROMPTEX_*.md` and the git log. The 2 going-forward templates
were renamed to describe what they do instead of when they were written:

| Going-forward name | Original name | Purpose |
|---|---|---|
| `scripts/redteam/prompt_exfil/exfil_per_agent_enum.py` | `promptex_stage4_agents.py` | One probe per known agent (basic triggers) |
| `scripts/redteam/prompt_exfil/exfil_full_prompt_capture.py` | `promptex_stage6_fullprompts.py` | Per-agent uncapped drain (after enum confirms dispatch) |

The `promptex_` prefix decoded as "prompt exfiltration" and `stageN`
reflected the chronological order during the May 2026 engagement, not
what each script does. Avoid that pattern in future scripts.
