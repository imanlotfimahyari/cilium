#!/usr/bin/env python3
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
# Copyright Authors of Cilium

"""Run the same explicit VM coverage sequentially on supplied trusted kernels.

The JSON config contains a kernels list of {name, kernel, modules}, optionally
with previous_agent_mode and required_tests for per-kernel transition coverage. Supply
ordinary privileged_vm.py artifact/coverage arguments after --. Failure on one
kernel does not erase its report or prevent the other kernels being tested.
"""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("vm_args", nargs=argparse.REMAINDER)
    args = p.parse_args()
    if not args.vm_args or args.vm_args[0] != "--":
        p.error("supply privileged_vm.py arguments after --")
    cases = json.loads(args.config.read_text())["kernels"]
    names = [c["name"] for c in cases]
    if not cases or len(set(names)) != len(names) or any(not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", n) for n in names):
        p.error("kernel names must be distinct safe labels")
    args.output.mkdir(parents=True, exist_ok=True)
    report = {"status": "FAIL", "kernels": {}}
    (args.output / "matrix.json").write_text(json.dumps(report, indent=2) + "\n")
    runner = Path(__file__).with_name("privileged_vm.py")
    for case in cases:
        name = case["name"]
        result_file = args.output / (name + ".json")
        result_file.unlink(missing_ok=True)
        if not Path(case["kernel"]).is_file() or not Path(case["modules"]).is_dir():
            report["kernels"][name] = {"status": "BLOCKED", "reason": "trusted kernel or modules missing"}
            continue
        command = [sys.executable, str(runner), *args.vm_args[1:],
                   "--kernel", case["kernel"], "--module-root", case["modules"],
                   "--log", str(args.output / (name + ".log")), "--report", str(result_file)]
        if "previous_agent_mode" in case:
            command += ["--previous-agent-mode", case["previous_agent_mode"]]
        for test in case.get("required_tests", []):
            command += ["--require-test", test]
        code = subprocess.run(command, check=False).returncode
        if result_file.exists():
            result = json.loads(result_file.read_text())
            if code != 0:
                result["status"] = "FAIL"
        else:
            result = {"status": "FAIL", "reason": "runner produced no current evidence", "exit": code}
        report["kernels"][name] = result
        (args.output / "matrix.json").write_text(json.dumps(report, indent=2) + "\n")
    if all(r["status"] == "PASS" for r in report["kernels"].values()):
        report["status"] = "PASS"
    (args.output / "matrix.json").write_text(json.dumps(report, indent=2) + "\n")
    if report["status"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
