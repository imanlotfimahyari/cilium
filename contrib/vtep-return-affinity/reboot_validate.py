#!/usr/bin/env python3
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
# Copyright Authors of Cilium

"""Validate controller recovery across two disconnected kernel boots.

Pass ordinary privileged_vm.py artifact arguments after --. A new disposable
ext4 image is created internally; no existing disk is formatted or attached.
Logs and individual machine-readable reports are retained in --output.
"""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("vm_args", nargs=argparse.REMAINDER)
    args = p.parse_args()
    vm_args = args.vm_args
    if not vm_args or vm_args[0] != "--":
        p.error("supply privileged_vm.py artifact arguments after --")
    args.output.mkdir(parents=True, exist_ok=True)
    result = {"status": "FAIL", "scope": "controller across two actual VM boots", "phases": {}}
    report = args.output / "reboot.json"
    runner = Path(__file__).with_name("privileged_vm.py")
    try:
        with tempfile.TemporaryDirectory(prefix="vtep-reboot-") as tmp:
            disk = Path(tmp) / "recovery.ext4"
            with disk.open("xb") as image:
                image.truncate(32 << 20)
            subprocess.run(["mkfs.ext4", "-q", "-F", str(disk)], check=True)
            for phase in ["prepare", "verify"]:
                phase_report = args.output / (phase + ".json")
                # A stale report must never count as evidence for a new run.
                phase_report.unlink(missing_ok=True)
                command = [sys.executable, str(runner), *vm_args[1:],
                           "--recovery-disk", str(disk), "--recovery-stage", phase,
                           "--agent-test-run", "^TestPrivilegedRebootRecovery$",
                           "--require-test", "TestPrivilegedRebootRecovery",
                           "--log", str(args.output / (phase + ".log")),
                           "--report", str(phase_report)]
                subprocess.run(command, check=True)
                evidence = json.loads(phase_report.read_text())
                result["phases"][phase] = evidence
                if evidence["status"] != "PASS":
                    raise RuntimeError("recovery phase did not pass: " + phase)
        result["status"] = "PASS"
    except (OSError, ValueError, subprocess.CalledProcessError, RuntimeError) as exc:
        result["error"] = str(exc)
        raise
    finally:
        report.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
