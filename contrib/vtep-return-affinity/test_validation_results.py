# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
# Copyright Authors of Cilium

import unittest

from validation_results import validate_output


class ValidationEvidenceTests(unittest.TestCase):
    def test_success_records_passes_and_optional_skips(self):
        output = """VTEP_SUITE_BEGIN=live
--- PASS: TestMapped (1.00s)
--- SKIP: TestOptional (0.00s)
VTEP_SUITE_EXIT=live:0
VTEP_VM_EXIT=0
"""
        self.assertEqual(validate_output(output, ["live"], ["TestMapped"])["status"], "PASS")
        self.assertEqual(validate_output(output, ["live"], ["TestOptional"])["status"], "FAIL")

    def test_empty_skipped_failed_truncated_and_ambiguous_runs_fail(self):
        for body in [
            "testing: warning: no tests to run",
            "--- SKIP: TestRequired (0.00s)",
            "--- PASS: TestOther (0.00s)",
            "--- PASS: TestRequired (0.00s)\n--- FAIL: TestOther (0.00s)",
            "--- PASS: TestRequired (0.00s)\n--- SKIP: TestRequired/variant (0.00s)",
        ]:
            with self.subTest(body=body):
                output = f"VTEP_SUITE_BEGIN=live\n{body}\nVTEP_SUITE_EXIT=live:0\nVTEP_VM_EXIT=0\n"
                self.assertEqual(validate_output(output, ["live"], ["TestRequired"])["status"], "FAIL")
        valid = "VTEP_SUITE_BEGIN=live\n--- PASS: TestRequired (0.00s)\nVTEP_SUITE_EXIT=live:0\nVTEP_VM_EXIT=0\n"
        for output in [valid.replace("VTEP_SUITE_EXIT=live:0", ""), valid + "VTEP_VM_EXIT=0\n",
                       valid.replace("live:0", "live:1"), valid.replace("VTEP_VM_EXIT=0", "")]:
            self.assertEqual(validate_output(output, ["live"], ["TestRequired"])["status"], "FAIL")
        self.assertEqual(validate_output(valid, ["live", "agent"])["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
