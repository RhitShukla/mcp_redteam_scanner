# scripts/redteam/prompt_exfil/

System-prompt exfiltration campaign — all stages live here. They're stages
of the **same** campaign, not separate techniques, which is why they share
a folder.

## Naming convention (maturity signal)

| Prefix | Meaning |
|---|---|
| `exfil_*.py` | **Refactored, manifest-driven.** Uses `src.redteam.target.Manifest` + `OrbitShiftAdapter` (or any future adapter). Reads URLs/endpoints from the engagement's `manifest.yml`. Works against any target whose manifest is filled in. Run these first. |
| `promptex_*.py` | **Historical, OrbitShift-hardcoded.** Each is frozen for the evidence chain of the May 2026 engagement (referenced from `reports/PROMPTEX_*.md` and the git log). The technique patterns inside are reusable but the URLs/auth-handling are baked-in. Read these for ideas; copy the pattern shape into a new manifest-driven script. |

## Campaign workflow

The natural progression — also the order in which these stages were
developed during the OrbitShift engagement, hence the chronological
`stage<N>` numbers on the historical files:

| Stage | File (active) | File (historical equivalent) | Purpose |
|---|---|---|---|
| 1. Sweep ideas | — | [`promptex_probe.py`](promptex_probe.py) | First sweep: try all 6 attack ideas against the target (cust-instruction poison, PPT context injection, persona injection, AskOS chat, auto-title leak, tools-schema reflection). Identify which work. |
| 2. Iterate with bug fixes | — | [`promptex_stage2.py`](promptex_stage2.py) | Same 6 ideas with the AskOS path bug fixed + chunk-redirect variants. |
| 3. Uncapped drain | — | [`promptex_stage3.py`](promptex_stage3.py) | Same probes with byte cap raised to 1.5 MB. Captures full SSE responses for the ideas that the cap was truncating. |
| 4. Per-agent enumeration | **[`exfil_per_agent_enum.py`](exfil_per_agent_enum.py)** | (was `promptex_stage4_agents.py`) | One probe per known agent (19 agents × JSON-wrapper tail). Discovers which agents actually dispatch vs. which the classifier handles in-character. |
| 5. Strong category triggers | — | [`promptex_stage5_agents.py`](promptex_stage5_agents.py) | Per-agent with category-specific triggers (PMB / PPT / SQL phrases) — forces dispatch when stage 4's generic triggers didn't. |
| 6. Full-prompt capture | **[`exfil_full_prompt_capture.py`](exfil_full_prompt_capture.py)** | (was `promptex_stage6_fullprompts.py`) | Uncapped (15 MB) per-agent capture targeting only agents stage 5 confirmed dispatch. Recovers complete prompts. |
| 7. Retry refused agents | — | [`promptex_stage7_final.py`](promptex_stage7_final.py) | Targeted retries on agents that refused the JSON-wrapper exfil — varied phrasings. |

## When to use which

- **New engagement, fresh target** → start with the two refactored scripts
  (`exfil_per_agent_enum.py` then `exfil_full_prompt_capture.py`). They read
  the manifest, work against any target.
- **Refactored scripts hit a wall** (refusal, novel target shape, etc.) →
  open the relevant historical `promptex_*.py` for the pattern (idea sweep
  / chunk-redirect / strong trigger / retry shape). Copy the pattern shape,
  rewrite it manifest-driven, point it at your engagement.

The historical files should NOT be edited — they're frozen for the
evidence chain. They live here (not in `engagements/orbitshift/`) because
their technique patterns belong to anyone working on prompt exfiltration,
not just OrbitShift.

## Invocation

```bash
# Refactored (any target):
python3 scripts/redteam/prompt_exfil/exfil_per_agent_enum.py engagements/orbitshift
python3 scripts/redteam/prompt_exfil/exfil_full_prompt_capture.py engagements/orbitshift

# Historical (OrbitShift-hardcoded; expects token at engagements/orbitshift/token_tenant_201.txt):
python3 scripts/redteam/prompt_exfil/promptex_probe.py
```

## See also

- [`~/.claude/skills/prompt-exfil/SKILL.md`](../../../../.claude/skills/prompt-exfil/SKILL.md) — the workflow skill that orchestrates these.
- [`src/redteam/core/payloads.py`](../../../src/redteam/core/payloads.py) — the payload constants (`JSON_WRAPPER_TAIL`, `CHUNK_REDIRECT`, etc.) the refactored scripts use.
- Memory entries [`exfil-json-wrapper`](../../../../.claude/projects/-Users-manish-Documents-augment-projects-HuggingFaceExp-MCP-MCPRedTeam/memory/exfil-json-wrapper.md), [`exfil-chunk-redirect`](../../../../.claude/projects/-Users-manish-Documents-augment-projects-HuggingFaceExp-MCP-MCPRedTeam/memory/exfil-chunk-redirect.md) — the cross-engagement learnings these scripts demonstrate.
