#!/usr/bin/env python3
"""Run the acceptance suite in parallel shards for a quick local signal.

Splits the collected nodes across several `tests/run-acceptance.sh` processes,
each with its own gate vector. Timing/soak/slow nodes run in a second phase,
after the rest finish, so the rest cannot starve a latency budget of CPU. Both
phases run at most -j processes at once. The suite itself is unchanged.

This is a developer check, not the Validator invocation: each shard's census
and gate vector cover only its own nodes. Use `tests/run-acceptance.sh` for a
verdict-bearing run.

Usage:
  KINBASE_BIN=$PWD/target/debug/kinbase tools/parallel_acceptance.py [-j N] [pytest args...]
  e.g. tools/parallel_acceptance.py -j 8 -m v3
"""

import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

RUNNER = Path(__file__).resolve().parent.parent / "tests" / "run-acceptance.sh"
SERIAL = "timing or soak or slow"
OUTCOMES = ("passed", "failed", "error", "skipped", "xfailed", "xpassed")


def collect(args: list[str]) -> list[str]:
    # Collection must not overwrite a gate vector the caller points at.
    env = {k: v for k, v in os.environ.items() if k != "KINBASE_ACCEPT_GATE_VECTOR"}
    out = subprocess.run(
        [str(RUNNER), "--collect-only", "-q", *args],
        capture_output=True, text=True, env=env,
    )
    if out.returncode not in (0, 5):  # 5: nothing matched the filter
        sys.exit(f"collection failed:\n{out.stdout[-3000:]}{out.stderr[-3000:]}")
    return [line for line in out.stdout.splitlines() if "::" in line and not line.startswith(" ")]


def summary(text: str) -> dict[str, int] | None:
    """Counts from pytest's final summary line, or None when there is none."""
    for line in reversed(text.splitlines()):
        if re.search(r" in [0-9.]+s", line) and re.search(r"\d+ (" + "|".join(OUTCOMES) + ")", line):
            counts = {key: 0 for key in OUTCOMES}
            for number, key in re.findall(r"(\d+) (passed|failed|errors?|skipped|xfailed|xpassed)", line):
                counts["error" if key.startswith("error") else key] += int(number)
            return counts
    return None


def main() -> int:
    argv = sys.argv[1:]
    jobs = max(2, (os.cpu_count() or 4) // 2)
    if argv[:1] == ["-j"]:
        if len(argv) < 2 or not argv[1].isdigit() or int(argv[1]) < 1:
            sys.exit("-j needs a whole number of at least 1")
        jobs, argv = int(argv[1]), argv[2:]
    marker = None
    if "-m" in argv:
        at = argv.index("-m")
        if at + 1 >= len(argv):
            sys.exit("-m needs a marker expression")
        marker, argv = argv[at + 1], argv[:at] + argv[at + 2:]

    every = collect([*argv, "-m", marker] if marker else argv)
    serial = sorted(set(collect([*argv, "-m", f"({marker}) and ({SERIAL})" if marker else SERIAL])))
    rest = [node for node in every if node not in serial]
    phases = [
        [rest[i::jobs] for i in range(jobs) if rest[i::jobs]],
        [serial[i::jobs] for i in range(jobs) if serial[i::jobs]],
    ]

    work = Path(tempfile.mkdtemp(prefix="kinbase-parallel-acceptance-"))
    started = time.monotonic()
    print(f"{len(every)} nodes: {len(rest)} in {len(phases[0])} shards, then {len(serial)} timing nodes in {len(phases[1])}; logs in {work}")
    totals = {key: 0 for key in OUTCOMES}
    failed, broken, index = [], [], 0
    for shards in phases:
        running = []
        for shard in shards:
            env = dict(os.environ, KINBASE_ACCEPT_GATE_VECTOR=str(work / f"gates-{index}.json"))
            log = open(work / f"shard-{index}.log", "w")
            # -rfE: list failures and errors (it replaces addopts' -ra).
            running.append((index, len(shard), log, subprocess.Popen(
                [str(RUNNER), "-q", "-rfE", *argv, *shard],
                stdout=log, stderr=subprocess.STDOUT, env=env,
            )))
            index += 1
        for shard_index, dispatched, log, process in running:
            status = process.wait()
            log.close()
            path = work / f"shard-{shard_index}.log"
            text = path.read_text()
            failed += re.findall(r"^(?:FAILED|ERROR) (\S+)", text, re.M)
            counts = summary(text)
            # A shard is only trusted when pytest finished it: a summary line
            # whose counts cover every node it was given, and exit 0 or 1.
            if counts is None or status not in (0, 1) or sum(counts.values()) < dispatched:
                broken.append(f"shard {shard_index} (exit {status}, {dispatched} nodes): {path}")
                continue
            for key in OUTCOMES:
                totals[key] += counts[key]

    for node in sorted(set(failed)):
        print(f"FAILED {node}")
    for line in broken:
        print(f"INCOMPLETE {line}")
    counted = ", ".join(f"{totals[key]} {key}" for key in OUTCOMES if totals[key] or key in ("passed", "failed"))
    print(f"{counted} of {len(every)} nodes in {time.monotonic() - started:.0f}s")
    if broken:
        return 2
    return 1 if failed or totals["failed"] or totals["error"] else 0


if __name__ == "__main__":
    sys.exit(main())
