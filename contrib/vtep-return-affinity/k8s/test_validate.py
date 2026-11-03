# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

import importlib.util
from pathlib import Path
import subprocess
import unittest
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location("validate", Path(__file__).with_name("validate.py"))
validate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validate)


class LabSafetyTests(unittest.TestCase):
    def test_context_never_defaults_or_accepts_non_lab_names(self):
        for context in ("", "default", "production", "kind", "kind-vtep-affinity-lab/other", "kind-vtep-affinity-lab;cmd"):
            with self.assertRaises(ValueError):
                validate.context_guard(context)
        validate.context_guard("kind-vtep-affinity-lab")
        validate.context_guard("kind-vtep-affinity-lab-kernel68")

    def test_endpoint_match_requires_the_correct_namespace(self):
        wrong = {"id": 1, "status": {"external-identifiers": {"pod-name": "other/server"}}}
        right = {"id": 2, "status": {"external-identifiers": {"k8s-namespace": "lab", "k8s-pod-name": "server"}}}
        self.assertIs(validate.endpoint_for([wrong, right], "lab", "server"), right)
        self.assertIsNone(validate.endpoint_for([wrong], "lab", "server"))

    def test_failed_exec_cannot_be_reported_as_policy_enforcement(self):
        lab = validate.Lab(SimpleNamespace(context="kind-vtep-affinity-lab"))
        lab.client_pod = lambda role: {"metadata": {"name": "client"}}
        lab.run = lambda *args, **kw: subprocess.CompletedProcess([], 1, "", "unable to reach API server")
        with self.assertRaises(RuntimeError):
            lab.request("denied", "192.0.2.1:8080")
        lab.run = lambda *args, **kw: subprocess.CompletedProcess([], 1, "", "TCP connection failed\n")
        self.assertFalse(lab.request("denied", "192.0.2.1:8080"))

    def test_cleanup_attempts_uncordon_when_namespace_cleanup_fails(self):
        lab = validate.Lab(SimpleNamespace(context="kind-vtep-affinity-lab"))
        lab.created, lab.cordoned = True, "lab-node"
        attempts = []
        def run(*args, **kw):
            attempts.append(args[0])
            if args[0] == "delete":
                raise RuntimeError("failed")
        lab.run = run
        with self.assertRaises(RuntimeError):
            lab.close()
        self.assertEqual(attempts, ["delete", "uncordon"])


if __name__ == "__main__":
    unittest.main()
