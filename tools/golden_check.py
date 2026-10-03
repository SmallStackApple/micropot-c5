#!/usr/bin/env python3
"""Golden-file behavior regression check for MicroPot-C5 event logs.

Compares two JSONL captures from log_collector.py (typically produced by
running tools/mock_client.py against an old and a new firmware build) and
reports whether the event sequences are behaviorally identical.

Typical workflow:
    1. Flash the old (known-good) firmware.
    2. Start tools/log_collector.py, run tools/mock_client.py, stop the
       collector and save the capture as baseline.jsonl.
    3. Flash the new firmware, repeat the run, save as candidate.jsonl.
    4. python3 golden_check.py baseline.jsonl candidate.jsonl --ignore sid

Volatile top-level fields (ts, boot, seq, sip, sport) are masked by
default; use --ignore <field> to mask additional top-level fields such as
the session id (sid). Lines that fail to parse as JSON are skipped, since
the collector file may contain unrelated output.

Exit codes: 0 = sequences match, 1 = differences found, 2 = file error.

Examples:
    python3 golden_check.py logs/baseline.jsonl logs/candidate.jsonl
    python3 golden_check.py a.jsonl b.jsonl --ignore sid --verbose
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap

DEFAULT_MASK = ("ts", "boot", "seq", "sip", "sport")


def load_events(path: str) -> list[dict]:
    """Parse a JSONL capture, skipping blank and non-JSON lines."""
    events = []
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(evt, dict):
                events.append(evt)
    return events


def mask_event(evt: dict, fields: set[str]) -> dict:
    return {k: v for k, v in evt.items() if k not in fields}


def show_context(label: str, events: list[dict], idx: int) -> None:
    """Pretty-print events around idx (one before/after) from one capture."""
    for j in (idx - 1, idx, idx + 1):
        if j < 0:
            continue
        marker = ">>" if j == idx else "  "
        if j < len(events):
            pretty = json.dumps(events[j], indent=2, sort_keys=True)
            print(f"{marker} {label}[{j}]:")
            print(textwrap.indent(pretty, "    "))
        else:
            print(f"{marker} {label}[{j}]: <no event>")


def main() -> int:
    parser = argparse.ArgumentParser(description="MicroPot-C5 golden event-log check")
    parser.add_argument("baseline", help="JSONL capture from the known-good firmware")
    parser.add_argument("candidate", help="JSONL capture from the firmware under test")
    parser.add_argument("--ignore", action="append", default=[], metavar="FIELD",
                        help="extra top-level field to mask (repeatable, e.g. sid)")
    parser.add_argument("--verbose", action="store_true",
                        help="print a per-event comparison line")
    args = parser.parse_args()

    try:
        base = load_events(args.baseline)
        cand = load_events(args.candidate)
    except OSError as e:
        print(f"ERROR {e}")
        return 2

    masked = set(DEFAULT_MASK) | set(args.ignore)
    base_m = [mask_event(e, masked) for e in base]
    cand_m = [mask_event(e, masked) for e in cand]

    print(f"baseline : {len(base)} events ({args.baseline})")
    print(f"candidate: {len(cand)} events ({args.candidate})")
    print(f"masked   : {', '.join(sorted(masked))}")

    overlap = min(len(base_m), len(cand_m))
    diffs = [i for i in range(overlap) if base_m[i] != cand_m[i]]
    diff_count = len(diffs) + abs(len(base_m) - len(cand_m))

    if args.verbose:
        for i in range(overlap):
            status = "DIFF" if i in diffs else "ok  "
            print(f"[{i:>4}] {status} {base_m[i].get('evt', '?')}")
        for i in range(overlap, max(len(base_m), len(cand_m))):
            side = "baseline-only" if i < len(base_m) else "candidate-only"
            print(f"[{i:>4}] DIFF {side}")

    if diff_count == 0:
        print(f"\nGOLDEN MATCH ({len(base_m)} events)")
        return 0

    first = diffs[0] if diffs else overlap
    print(f"\nGOLDEN DIFF: {diff_count} difference(s), first at event #{first}\n")
    show_context("baseline", base_m, first)
    show_context("candidate", cand_m, first)
    return 1


if __name__ == "__main__":
    sys.exit(main())
