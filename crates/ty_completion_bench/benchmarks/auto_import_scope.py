#!/usr/bin/env python3
"""Measure cached auto-import completions across scope and candidate cardinalities.

This adapts the repository's existing ``ty_completion_bench`` developer tool.
Each scenario builds a first-party catalog of matching symbols and a main module
with visible bindings, then uses the tool's own timed repeated-completion path.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SCENARIOS = (
    ("small", 64, 64),
    ("medium", 256, 256),
    ("large", 512, 1024),
)
ITERATIONS = 50
METRIC = "ty_ide_auto_import_completion_ns_per_request"
COMPLETION_COUNT_METRIC = "ty_ide_auto_import_completion_count"
DURATION_RE = re.compile(
    r"time per completion request: (?P<value>\d+(?:\.\d+)?)(?P<unit>ns|µs|us|ms|s)\b"
)
COMPLETION_COUNT_RE = re.compile(r"^found (?P<count>\d+) completions$", re.MULTILINE)
NANOSECONDS_PER_UNIT = {
    "ns": 1.0,
    "µs": 1_000.0,
    "us": 1_000.0,
    "ms": 1_000_000.0,
    "s": 1_000_000_000.0,
}

WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
FIXTURE_ROOT = WORKSPACE_ROOT / "crates/ty_completion_bench/.perfloop-auto-import-scope"


def prepare_fixtures() -> None:
    """Create deterministic first-party projects for the three workload shapes."""
    for name, candidate_count, binding_count in SCENARIOS:
        scenario_root = FIXTURE_ROOT / name
        scenario_root.mkdir(parents=True, exist_ok=True)
        (scenario_root / "pyproject.toml").write_text(
            "[project]\n"
            f'name = "auto-import-scope-{name}"\n'
            'version = "0.1.0"\n'
            'requires-python = ">=3.10"\n',
            encoding="utf-8",
        )
        (scenario_root / "catalog.py").write_text(
            "".join(f"class Target{index:04}: ...\n" for index in range(candidate_count)),
            encoding="utf-8",
        )
        main = "".join(
            f"scope_binding_{index:04} = {index}\n" for index in range(binding_count)
        ) + "Target\n"
        (scenario_root / "main.py").write_text(main, encoding="utf-8")
        # The cursor is immediately after the nonempty query, before its newline.
        (scenario_root / "cursor-offset").write_text(
            str(len(main.encode("utf-8")) - 1), encoding="utf-8"
        )


def duration_to_nanoseconds(value: str, unit: str) -> float:
    return float(value) * NANOSECONDS_PER_UNIT[unit]


def run_scenario(name: str, minimum_candidates: int, iterations: int) -> tuple[float, int]:
    scenario_root = FIXTURE_ROOT / name
    main = (scenario_root / "main.py").resolve()
    offset = (scenario_root / "cursor-offset").read_text(encoding="utf-8").strip()
    benchmark_binary = os.environ.get("PERFLOOP_BENCH_BIN")
    if benchmark_binary is None:
        raise RuntimeError("PERFLOOP_BENCH_BIN was not set by the benchmark build")
    command = [benchmark_binary, str(main), offset, "--iters", str(iterations)]
    completed = subprocess.run(
        command,
        cwd=WORKSPACE_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    output = completed.stdout
    if completed.returncode:
        raise RuntimeError(f"{name} scenario failed:\n{output}")

    durations = list(DURATION_RE.finditer(output))
    if len(durations) != 1:
        raise RuntimeError(
            f"{name} scenario emitted {len(durations)} per-request timings, expected one:\n{output}"
        )
    counts = list(COMPLETION_COUNT_RE.finditer(output))
    if len(counts) != 1:
        raise RuntimeError(
            f"{name} scenario emitted {len(counts)} completion counts, expected one:\n{output}"
        )

    completion_count = int(counts[0]["count"])
    if completion_count < minimum_candidates:
        raise RuntimeError(
            f"{name} scenario returned {completion_count} completions, "
            f"expected at least {minimum_candidates}:\n{output}"
        )
    duration = durations[0]
    return duration_to_nanoseconds(duration["value"], duration["unit"]), completion_count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--iterations", type=int, default=ITERATIONS)
    args = parser.parse_args()

    prepare_fixtures()
    if args.prepare:
        return 0
    if args.iterations <= 0:
        parser.error("--iterations must be positive")

    try:
        results = [
            run_scenario(name, candidate_count, args.iterations)
            for name, candidate_count, _ in SCENARIOS
        ]
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 1

    average_nanoseconds = sum(duration for duration, _ in results) / len(results)
    completion_count = sum(count for _, count in results)
    print(json.dumps({"metric": METRIC, "value": average_nanoseconds}))
    print(json.dumps({"metric": COMPLETION_COUNT_METRIC, "value": completion_count}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
