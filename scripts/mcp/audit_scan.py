"""
MCP Red Team — Scan Request Counter

Reads a scan result JSON and prints the total number of requests made,
broken down by MCP method and per tool.

Usage:
    python audit_scan.py output/scan_20260407_225748.json
"""

import json
import sys
from collections import Counter


def main():
    if len(sys.argv) < 2:
        print("Usage: python audit_scan.py <scan_file.json>")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        scan = json.load(f)

    traces = scan.get("traces", [])
    target = scan.get("target", "?")
    findings = scan.get("findings", [])

    # Count by method
    methods = Counter()
    tools = Counter()
    for t in traces:
        method = t.get("method", "unknown")
        methods[method] += 1
        if method == "tools/call":
            name = t.get("request", {}).get("name", "unknown")
            tools[name] += 1

    # Print
    print(f"Scan:     {sys.argv[1]}")
    print(f"Target:   {target}")
    print(f"Findings: {len(findings)}")
    print()
    print(f"Total requests: {len(traces)}")
    print()

    print("By method:")
    for method, count in methods.most_common():
        print(f"  {method:<30s} {count}")

    print()
    print("By tool:")
    for tool, count in tools.most_common():
        print(f"  {tool:<45s} {count}")
    print(f"  {'─' * 45} {'─' * 3}")
    print(f"  {'Total tool calls':<45s} {sum(tools.values())}")


if __name__ == "__main__":
    main()
