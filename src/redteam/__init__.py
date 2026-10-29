"""redteam — manifest-driven web/LLM red-team probe library.

Core (target-agnostic): src.redteam.core.{client,jwt,sse,payloads,leak,output}
Target framework:       src.redteam.target  (Manifest, TargetAdapter ABC)
Target adapters:        src.redteam.targets.<target>

Usage:
    from src.redteam.target import Manifest
    from src.redteam.targets.orbitshift import OrbitShiftAdapter

    manifest = Manifest.load("engagements/orbitshift")
    adapter  = OrbitShiftAdapter(manifest, token_role="tenant_201")
    response = adapter.chat("Hello, what can you do?")

See ~/.claude/skills/{prompt-exfil,cross-tenant-canary,har-inventory}/SKILL.md
for the workflows this library powers.
"""

from src.redteam.target import Manifest, TargetAdapter

__all__ = ["Manifest", "TargetAdapter"]
