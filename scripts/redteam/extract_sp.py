#!/usr/bin/env python3
"""Robust system_prompt extractor for raw stage-output .txt files.

Refactored 2026-05-20 to use src.redteam.core.leak.extract_system_prompt
(the state-machine extractor was moved into the shared library). The CLI
behaviour is unchanged.
"""
import sys
import pathlib

from src.redteam.core.leak import extract_system_prompt


def main():
    for p in sys.argv[1:]:
        d = pathlib.Path(p).read_text()
        sp = extract_system_prompt(d)
        print("=" * 72)
        print("FILE:", p, "size", len(d))
        if sp is None:
            print("  no system_prompt key found")
            continue
        print(f"  chars={len(sp)}")
        print("--- prompt (first 4KB) ---")
        print(sp[:4000])
        print("...")
        print("--- prompt (last 1KB) ---")
        print(sp[-1000:])
        out = pathlib.Path(p).parent / f"PROMPT_{pathlib.Path(p).stem}.txt"
        out.write_text(sp)
        print(f"  wrote {out}")


if __name__ == "__main__":
    main()
