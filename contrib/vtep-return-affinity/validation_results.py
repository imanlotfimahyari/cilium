# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
# Copyright Authors of Cilium

"""Evidence checks shared by the disconnected VM runner and kernel matrix."""

import re


def validate_output(output, suites, required_tests=()):
    """Never infer coverage from a zero exit status alone."""
    results = {}
    active = None
    errors = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("VTEP_SUITE_BEGIN="):
            name = line.split("=", 1)[1]
            if active is not None or name in results or name not in suites:
                errors.append("unexpected or overlapping suite: " + name)
            active = name
            results[name] = {"passed": [], "skipped": [], "failed": [], "exit": None}
        elif line.startswith("VTEP_SUITE_EXIT="):
            fields = line.split("=", 1)[1].split(":")
            if len(fields) != 2 or fields[0] != active:
                errors.append("unmatched suite exit")
                continue
            try:
                results[active]["exit"] = int(fields[1])
            except ValueError:
                errors.append("invalid suite exit")
            active = None
        elif active is not None:
            match = re.match(r"--- (PASS|SKIP|FAIL): (\S+)", line)
            if match:
                field = {"PASS": "passed", "SKIP": "skipped", "FAIL": "failed"}[match[1]]
                results[active][field].append(match[2])
    if active is not None:
        errors.append("unfinished suite: " + active)
    for name in suites:
        result = results.get(name)
        if result is None:
            errors.append("missing suite: " + name)
        elif result["exit"] != 0 or result["failed"] or not result["passed"]:
            errors.append("suite failed or executed no passing tests: " + name)
    passed = {t for r in results.values() for t in r["passed"]}
    skipped = {t for r in results.values() for t in r["skipped"]}
    for name in required_tests:
        if name not in passed or any(t == name or t.startswith(name + "/") for t in skipped):
            errors.append("required test absent, skipped or incomplete: " + name)
    exits = re.findall(r"^VTEP_VM_EXIT=(\d+)\s*$", output, re.MULTILINE)
    if exits != ["0"]:
        errors.append("missing, repeated or unsuccessful VM exit")
    return {"status": "FAIL" if errors else "PASS", "suites": results, "errors": errors}
