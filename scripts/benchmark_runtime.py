#!/usr/bin/env python3
"""Interleave baseline/candidate AES workloads on the same machine and interpreter."""

import argparse
import importlib.util
import json
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path

import aes_core


def measure(operations, repeats):
    times = {name: [] for name in operations}
    names = list(operations)
    for repeat in range(repeats + 1):
        for name in names[repeat % len(names):] + names[:repeat % len(names)]:
            wall, cpu = time.perf_counter_ns(), time.process_time_ns()
            operations[name]()
            elapsed = ((time.perf_counter_ns() - wall) / 1e6, (time.process_time_ns() - cpu) / 1e6)
            if repeat:
                times[name].append(elapsed)
    return {name: {"wall_ms": statistics.median(t[0] for t in values),
                   "cpu_ms": statistics.median(t[1] for t in values)} for name, values in times.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-core", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=21)
    parser.add_argument("--out", type=Path, default=Path("results/runtime/comparison.json"))
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    spec = importlib.util.spec_from_file_location("baseline", args.baseline_core)
    baseline = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(baseline)
    rows = []
    for size in (128, 512, 1024):
        payload, key = bytes(i % 256 for i in range(size)), bytes(range(16))
        operations = {}
        for label, module in (("before", baseline), ("after", aes_core)):
            ciphertext = module.encrypt_data(payload, key)
            assert module.decrypt_data(ciphertext, key) == payload
            operations[f"{label}_encryption"] = lambda m=module, p=payload, k=key: m.encrypt_data(p, k)
            operations[f"{label}_decryption"] = lambda m=module, c=ciphertext, k=key: m.decrypt_data(c, k)
        rows.append({"payload_bytes": size, **measure(operations, args.repeats)})
    startup = measure({label: lambda p=path: subprocess.run(
        [sys.executable, "-c", "import runpy,sys; runpy.run_path(sys.argv[1])", str(p)], check=True)
        for label, path in (("before", args.baseline_core), ("after", Path(aes_core.__file__)))}, 7)
    result = {"baseline_revision": "3ff4a89", "python": platform.python_version(),
              "platform": platform.platform(), "repeats": args.repeats,
              "statistic": "Interleaved medians after one warm-up; wall and process CPU time.",
              "python_and_import_wall_ms": {name: values["wall_ms"] for name, values in startup.items()},
              "workloads": rows}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
