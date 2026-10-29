"""Output-directory + JSON-saving + run-log helpers.

Generic conventions baked in:
  - timestamped raw_<CAMPAIGN>_<YYYYMMDD_HHMMSS>/ folder per stage
  - one JSON file per request, named <YYYYMMDD_HHMMSS_mmm>_<label>.json
  - one run_log.txt per stage

See CLAUDE.md "Output conventions" for the project-wide policy.
"""
from __future__ import annotations

import json
import pathlib
import datetime as dt
from typing import Any, Optional


def now_ts() -> str:
    """Sortable filename-safe timestamp with millisecond resolution."""
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]


def make_outdir(campaign: str, base_dir: Optional[str] = None) -> pathlib.Path:
    """Create a fresh raw_<CAMPAIGN>_<TIMESTAMP>/ folder and return its path.

    `base_dir` defaults to cwd. For OrbitShift-style engagements, pass the
    engagement's `04_Raw_Results/` folder.
    """
    base = pathlib.Path(base_dir) if base_dir else pathlib.Path.cwd()
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = base / f"raw_{campaign}_{ts}"
    out.mkdir(parents=True, exist_ok=True)
    return out


def save_json(path: pathlib.Path | str, obj: Any) -> None:
    """Write `obj` to `path` as indented JSON, with non-serializable objects
    coerced via str()."""
    pathlib.Path(path).write_text(
        json.dumps(obj, indent=2, default=str, ensure_ascii=False)
    )


class RunLog:
    """Append-only log file, one line per event."""

    def __init__(self, outdir: pathlib.Path | str, name: str = "run_log.txt"):
        self.path = pathlib.Path(outdir) / name
        self.path.touch()

    def write(self, msg: str) -> None:
        ts = dt.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        with self.path.open("a") as f:
            f.write(f"[{ts}] {msg}\n")

    def __call__(self, msg: str) -> None:
        self.write(msg)
        print(msg)
