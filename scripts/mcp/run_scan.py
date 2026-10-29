"""
MCP Red Team Scanner — Run all attack modules against a target endpoint.

Usage:
    python run_scan.py <endpoint_url> [--token TOKEN] [--auth-method bearer_token|api_key|none]
    python run_scan.py <endpoint_url> --browser-auth <login_url>

Examples:
    python run_scan.py http://localhost:9999/sse
    python run_scan.py http://localhost:9999/sse --token sk-my-secret
    python run_scan.py http://localhost:9999/sse --browser-auth https://app.skill10x.com/auth
"""

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from src.models import AuthMethod, TargetConfig, TransportType
from src.oauth_browser import browser_login
from src.probe_engine import ProbeEngine
from src.blueprint_analyzer import BlueprintAnalyzer
from src.attacks.a1_description_poisoning import A1DescriptionPoisoning
from src.attacks.a2_schema_manipulation import A2SchemaManipulation
from src.attacks.a3_auth_wall_break import A3AuthWallBreak
from src.attacks.a4_enumeration_leakage import A4EnumerationLeakage
from src.attacks.b1_parameter_injection import B1ParameterInjection
from src.attacks.b2_ssrf_probe import B2SSRFProbe
from src.attacks.b3_path_traversal import B3PathTraversal
from src.attacks.s1_ssrf import S1SSRF
from src.attacks.b5_error_info_disclosure import B5ErrorInfoDisclosure
from src.attacks.d1_sensitive_data import D1SensitiveData
from src.attacks.d2_api_key_stealing import D2APIKeyStealing
from src.attacks.e1_weak_auth import E1WeakAuth
from src.attacks.e3_tls_origin_validation import E3TLSOriginValidation
from src.attacks.e5_rate_limit_probe import E5RateLimitProbe
from src.attacks.mcp_tool_shadowing import MCPToolShadowing
from src.attacks.mcp_excessive_perms import MCPExcessivePerms


ATTACK_MODULES = [
    # Phase 1 - Access/Transport Gate Checks (E)
    E1WeakAuth,
    E3TLSOriginValidation,
    E5RateLimitProbe,
    MCPExcessivePerms,
    # Phase 2 - Tool Exposure & Trust Surface (A)
    A4EnumerationLeakage,
    MCPToolShadowing,
    A2SchemaManipulation,
    A1DescriptionPoisoning,
    # Phase 3 - Safe Active Injection Probes (B)
    B5ErrorInfoDisclosure,
    B1ParameterInjection,
    B3PathTraversal,
    B2SSRFProbe,
    # Deterministic oracle-backed SSRF detector
    S1SSRF,
    # Auth abuse depth module
    A3AuthWallBreak,
    # Data exfiltration modules
    D1SensitiveData,
    D2APIKeyStealing,
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="MCP Red Team Scanner")
    parser.add_argument("endpoint", help="MCP endpoint URL (e.g. http://localhost:9999/sse)")
    parser.add_argument("--token", default=None, help="Auth token")
    parser.add_argument(
        "--auth-method",
        default="none",
        choices=["none", "bearer_token", "api_key"],
        help="Authentication method (default: none)",
    )
    parser.add_argument(
        "--browser-auth",
        default=None,
        metavar="LOGIN_URL",
        help="Login via browser OAuth (e.g. https://app.skill10x.com/auth)",
    )
    parser.add_argument(
        "--callback-port",
        type=int,
        default=8765,
        help="Local port for OAuth callback (default: 8765)",
    )
    parser.add_argument(
        "--output",
        default="./output",
        help="Output directory for results (default: ./output)",
    )
    parser.add_argument(
    "--transport",
    choices=["sse", "streamable_http"],
    default="sse",
    help="MCP transport (default: sse)",
    )
    return parser.parse_args()


async def run_scan(config: TargetConfig) -> dict:
    engine = ProbeEngine(config)
    all_findings = []
    summaries = []
    sep = "=" * 60
    sub_sep = "-" * 60

    print(f"\n{sep}")
    print(f"  MCP Red Team Scan")
    print(f"  Target: {config.endpoint_url}")
    print(f"  Auth:   {config.auth_method.value}")
    print(f"{sep}\n")

    # Connect and discover capabilities
    async with engine.connect() as session_id:
        session = engine.sessions[session_id]
        caps = session.server_capabilities
        print(f"[+] Connected (session: {session_id[:8]}...)")
        print(f"[+] Server capabilities: {json.dumps(caps, indent=2, default=str)}\n")

        # ── Phase 0: Passive Analysis (Blueprint Analyzer) ──
        print(f"\n{sub_sep}")
        print(f"  Phase 0: Passive Blueprint Analysis")
        print(f"{sub_sep}\n")

        analyzer = BlueprintAnalyzer(engine)
        blueprint_findings = await analyzer.analyze()
        all_findings.extend(blueprint_findings)
        engine.shared_context["phase0"] = {
            "tools": analyzer.discovered_tools,
            "resources": analyzer.discovered_resources,
            "prompts": analyzer.discovered_prompts,
            "findings": [f.model_dump(mode="json") for f in blueprint_findings],
            "summary": analyzer.summary(),
            "attack_map": analyzer.attack_surface_map(),
        }

        # Print discovery summary
        print(f"[+] Tools discovered: {len(analyzer.discovered_tools)}")
        for t in analyzer.discovered_tools:
            print(f"    - {t['name']}: {t.get('description', 'no description')[:60]}")

        print(f"[+] Resources discovered: {len(analyzer.discovered_resources)}")
        for r in analyzer.discovered_resources:
            print(f"    - {r.get('uri', r.get('name', 'unknown'))}")

        print(f"[+] Prompts discovered: {len(analyzer.discovered_prompts)}")
        for p in analyzer.discovered_prompts:
            print(f"    - {p['name']}")

        # Print blueprint findings
        if blueprint_findings:
            print(f"\n[!] Blueprint Analysis found {len(blueprint_findings)} issue(s):")
            for f in blueprint_findings:
                print(f"    [{f.severity.value}] {f.id}: {f.title}")
        else:
            print(f"\n[+] Blueprint Analysis: No passive findings.")

        summaries.append(analyzer.summary())

        # ── Phase 1+: Active Attack Modules ──
        print(f"\n{sub_sep}")
        print(f"  Running {len(ATTACK_MODULES)} active attack module(s)")
        print(f"{sub_sep}\n")

        for module_cls in ATTACK_MODULES:
            module = module_cls(engine)
            print(f"[*] Running: {module.module_id} — {module.name}")
            print(f"    {module.description}\n")

            try:
                findings = await module.run()
            except Exception as exc:
                print(f"    [!] Module failed: {exc}\n")
                continue

            all_findings.extend(findings)
            summaries.append(module.summary())

            if findings:
                for f in findings:
                    print(f"    [{f.severity.value}] {f.id}: {f.title}")
                print()
            else:
                print(f"    No findings.\n")

    # Print summary
    print(f"{sep}")
    print(f"  Scan Complete")
    print(f"{sep}\n")
    print(f"  Total findings: {len(all_findings)}")

    severity_counts = {}
    for f in all_findings:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1
    for sev, count in severity_counts.items():
        print(f"    {sev}: {count}")

    print(f"  Total traces recorded: {len(engine.traces)}\n")

    # Build result
    result = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "target": config.endpoint_url,
        "auth_method": config.auth_method.value,
        "modules_run": len(ATTACK_MODULES),
        "total_findings": len(all_findings),
        "findings": [f.model_dump(mode="json") for f in all_findings],
        "module_summaries": summaries,
        "phase0": engine.shared_context.get("phase0", {}),
        "traces": [t.model_dump(mode="json") for t in engine.traces],
    }
    return result


def main():
    args = parse_args()

    # Resolve auth token
    token = args.token
    auth_method = args.auth_method

    if args.browser_auth:
        print("[*] Starting OAuth login flow...")
        token = browser_login(
            mcp_endpoint=args.endpoint,
            auth_server=args.browser_auth,
            callback_port=args.callback_port,
        )
        print(f"[DEBUG] ACCESS TOKEN: {token}")
        auth_method = "bearer_token"

    config = TargetConfig(
        endpoint_url=args.endpoint,
        transport=TransportType(args.transport),
        auth_method=AuthMethod(auth_method),
        auth_token=token,
        output_dir=args.output,
    )

    result = asyncio.run(run_scan(config))

    # Write results to file
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = output_dir / f"scan_{timestamp}.json"
    output_file.write_text(json.dumps(result, indent=2, default=str))
    print(f"  Results saved to: {output_file}\n")


if __name__ == "__main__":
    main()
