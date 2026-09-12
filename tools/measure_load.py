#!/usr/bin/env python3
"""Run the isolated 32x20 mock load test and record Linux process measurements.

Usage: python3 tools/measure_load.py [--output validation/load.json]
Requires the pinned Rust toolchain on PATH. No provider credentials or live calls.
"""

import argparse
import datetime
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("validation/load.json"))
    args = parser.parse_args()
    if platform.system() != "Linux":
        raise SystemExit("Run this measurement in Linux or WSL (wait4 reports peak RSS in KiB).")
    build = subprocess.run(
        ["cargo", "test", "--locked", "--lib", "--no-run", "--message-format=json"],
        text=True, capture_output=True, check=True,
    )
    executable = None
    for line in build.stdout.splitlines():
        artifact = json.loads(line)
        if (artifact.get("reason") == "compiler-artifact"
                and artifact.get("profile", {}).get("test")
                and artifact.get("executable")):
            executable = artifact["executable"]
    if executable is None:
        raise SystemExit("The library test executable was not produced.")
    test = "tests::load_32_simultaneous_default_batches_stays_bounded_and_releases_admission"
    start = time.monotonic()
    with tempfile.TemporaryFile(mode="w+b") as output:
        pid = os.fork()
        if pid == 0:
            os.dup2(output.fileno(), 1)
            os.dup2(output.fileno(), 2)
            os.execv(executable, [executable, test, "--exact", "--nocapture", "--test-threads=1"])
        _, status, usage = os.wait4(pid, 0)
        output.seek(0)
        transcript = output.read().decode("utf-8")
    print(transcript)
    result = {
        "recorded_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platform": platform.platform(),
        "logical_cpus": os.cpu_count(),
        "profile": "debug; service and mock provider in one isolated test process",
        "test": test,
        "simultaneous_requests": 32,
        "indicators_per_request": 20,
        "registered_providers": 2,
        "elapsed_seconds": round(time.monotonic() - start, 6),
        "peak_resident_kib": usage.ru_maxrss,
        "user_cpu_seconds": usage.ru_utime,
        "system_cpu_seconds": usage.ru_stime,
        "exit_code": os.waitstatus_to_exitcode(status),
    }
    metrics = re.search(r"LOAD_32X20 ([^\n]+)", transcript)
    if metrics:
        result["mock_metrics"] = {
            key: int(value) for key, value in re.findall(r"(\w+)=(\d+)", metrics.group(1))
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    raise SystemExit(result["exit_code"])


if __name__ == "__main__":
    main()
