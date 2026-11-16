#!/usr/bin/env python3
"""Run the acceptance suite in parallel shards for a quick local signal.

Splits the collected nodes across several `tests/run-acceptance.sh` processes,
each with its own vault and gate vector. Timing/soak/slow nodes run in a second
phase, one per process, after the rest finish, so the rest cannot starve a
latency budget of CPU. The suite itself is unchanged.

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


def collect(args: list[str]) -> list[str]:
    out = subprocess.run(
        [str(RUNNER), "--collect-only", "-q", *args],
        capture_output=True, text=True,
    )
    nodes = [line for line in out.stdout.splitlines() if "::" in line and not line.startswith(" ")]
    if out.returncode not in (0, 5):  # 5: nothing matched the filter
        sys.exit(f"collection failed:\n{out.stdout[-3000:]}{out.stderr[-3000:]}")
    return nodes


def main() -> int:
    argv = sys.argv[1:]
    jobs = max(2, (os.cpu_count() or 4) // 2)
    if argv[:1] == ["-j"]:
        jobs, argv = int(argv[1]), argv[2:]
    marker = None
    if "-m" in argv:
        at = argv.index("-m")
        marker, argv = argv[at + 1], argv[:at] + argv[at + 2:]

    every = collect([*argv, "-m", marker] if marker else argv)
    serial = set(collect([*argv, "-m", f"({marker}) and ({SERIAL})" if marker else SERIAL]))
    rest = [node for node in every if node not in serial]
    phases = [
        [rest[i::jobs] for i in range(jobs) if rest[i::jobs]],
        [[node] for node in sorted(serial)],
    ]

    work = Path(tempfile.mkdtemp(prefix="kinbase-parallel-acceptance-"))
    started = time.monotonic()
    print(f"{len(every)} nodes: {len(rest)} in {len(phases[0])} shards, then {len(serial)} timing nodes one per shard; logs in {work}")
    failed, passed, worst, index = [], 0, 0, 0
    for shards in phases:
        running = []
        for shard in shards:
            env = dict(
                os.environ,
                KINBASE_TESTER_VAULT=str(work / f"vault-{index}"),
                KINBASE_ACCEPT_GATE_VECTOR=str(work / f"gates-{index}.json"),
            )
            log = open(work / f"shard-{index}.log", "w")
            running.append((index, log, subprocess.Popen(
                [str(RUNNER), "-q", "-rf", *argv, *shard],
                stdout=log, stderr=subprocess.STDOUT, env=env,
            )))
            index += 1
        for shard_index, log, process in running:
            status = process.wait()
            log.close()
            text = (work / f"shard-{shard_index}.log").read_text()
            failed += re.findall(r"^(?:FAILED|ERROR) (\S+)", text, re.M)
            summary = text.strip().splitlines()[-1] if text.strip() else ""
            passed += sum(int(n) for n in re.findall(r"(\d+) passed", summary))
            # 1 is "tests failed" (counted above); anything else is a harness error.
            if status not in (0, 1):
                print(f"shard {shard_index} exited {status}; see {work / f'shard-{shard_index}.log'}")
                worst = status

    for node in sorted(set(failed)):
        print(f"FAILED {node}")
    print(f"{passed} passed, {len(set(failed))} failed in {time.monotonic() - started:.0f}s")
    return worst or (1 if failed else 0)


if __name__ == "__main__":
    sys.exit(main())
