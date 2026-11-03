# This file was not reviewed by a human before submission
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

    def test_external_policy_checks_use_fresh_tuples_and_restore_native_checks(self):
        lab = validate.Lab(SimpleNamespace(context="kind-vtep-affinity-lab", cilium_namespace="kube-system"))
        class Peers:
            peers = ["first", "second"]
            client = "198.18.0.9"
            allowed = False
            calls = []
            def configure(self, *args): pass
            def request(self, peer, target, port):
                self.calls.append((peer, port, self.allowed))
                return self.allowed
        lab.external = Peers()
        lab.get = lambda *args: {"status": {"addresses": [{"type": "InternalIP", "address": "192.0.2.1"}]}}
        lab.agent = lambda *args: {"metadata": {"name": "agent"}}
        def run(*args, **kwargs):
            if args[0] == "delete": lab.external.allowed = False
            return subprocess.CompletedProcess([], 0, "02:00:00:00:00:01", "")
        lab.run = run
        lab.apply = lambda policy: setattr(lab.external, "allowed", True)
        lab.wait = lambda predicate, *args: next(value for _ in range(10) if (value := predicate()))
        native = []
        lab.verify_policy = lambda server: native.append(True)
        server = {"spec": {"nodeName": "node"}, "status": {"podIP": "192.0.2.2"}}
        lab.verify_external(server)
        ports = [port for _, port, _ in lab.external.calls]
        self.assertEqual(len(ports), len(set(ports)))
        for peer in lab.external.peers:
            outcomes = [allowed for which, _, allowed in lab.external.calls if which == peer]
            self.assertEqual(outcomes, [True, False, False, False, True])
        self.assertEqual(native, [True])

    def test_external_cleanup_failure_does_not_skip_namespace_or_uncordon(self):
        lab = validate.Lab(SimpleNamespace(context="kind-vtep-affinity-lab"))
        lab.created, lab.cordoned = True, "lab-node"
        class Peers:
            def close(self): raise RuntimeError("cleanup failed")
        lab.external = Peers()
        attempts = []
        lab.run = lambda *args, **kw: attempts.append(args[0])
        with self.assertRaises(RuntimeError): lab.close()
        self.assertEqual(attempts, ["delete", "uncordon"])


if __name__ == "__main__":
    unittest.main()
