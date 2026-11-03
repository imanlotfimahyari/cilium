# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
# Copyright Authors of Cilium

"""Reject invalid transition evidence before allocating or booting a guest."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class TransitionPreflightTests(unittest.TestCase):
    def test_same_artifact_cannot_count_as_two_versions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            current, previous = root / "current", root / "previous"
            current.write_bytes(b"synthetic-public-agent")
            previous.write_bytes(current.read_bytes())
            args = self.arguments(root) + [
                "--full-agent", str(current), "--source-bpf", str(root),
                "--clang", str(current), "--netfilter-root", str(root),
                "--live-tests", str(current), "--previous-full-agent", str(previous),
                "--previous-source-bpf", str(root),
            ]
            result = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("two distinct agent binaries", result.stderr)
            self.assertFalse((root / "run.log").exists())

    def test_previous_binary_source_and_mode_must_be_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for extra, diagnostic in [
                (["--previous-full-agent", str(root / "previous")], "must be supplied together"),
                (["--previous-source-bpf", str(root)], "must be supplied together"),
                (["--previous-agent-mode", "missing-hashdance"], "requires a previous agent"),
            ]:
                with self.subTest(extra=extra):
                    result = subprocess.run(self.arguments(root) + extra, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn(diagnostic, result.stderr)
                    self.assertFalse((root / "run.log").exists())

    @staticmethod
    def arguments(root):
        return [sys.executable, str(Path(__file__).with_name("privileged_vm.py")),
                "--qemu-root", str(root), "--kernel", str(root / "kernel"),
                "--busybox", str(root / "busybox"), "--runner", str(root / "runner"),
                "--bpf-dir", str(root), "--log", str(root / "run.log")]


if __name__ == "__main__":
    unittest.main()
