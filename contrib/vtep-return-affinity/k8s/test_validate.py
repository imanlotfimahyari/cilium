# This file was not reviewed by a human before submission
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium

import importlib.util
from pathlib import Path
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

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

    def test_restart_rejects_stale_progress_and_reconnections(self):
        for reconnect in (False, True):
            with self.subTest(reconnect=reconnect):
                lab = validate.Lab(SimpleNamespace(context="kind-vtep-affinity-lab", cilium_namespace="kube-system",
                                                  restart_agent=True, drain_node=False))
                nodes = [{"metadata": {"name": n, "labels": {validate.LAB_LABEL: "true"}}, "spec": {}} for n in ("a", "b")]
                lab.get = lambda *args: {"items": nodes}
                server = {"metadata": {"name": "server", "uid": "old"}, "spec": {"nodeName": "a"}}
                lab.deploy = lambda nodes: server
                lab.server = lambda **kwargs: server
                lab.selected_endpoint = lambda pod: True
                lab.client_pod = lambda role: {"metadata": {"name": role}}
                lab.verify_policy = lambda pod: "192.0.2.2:8080"
                lab.verify_external = Mock(return_value="192.0.2.2:8080")
                lab.agent = lambda node, previous_uid=None: {"metadata": {"name": "agent", "uid": "new" if previous_uid else "old"}}
                lab.run = lambda *args, **kwargs: subprocess.CompletedProcess([], 0, "", "")
                native_reads = []
                native_values = iter([3, 10, 10, 14])
                def progress():
                    count = next(native_values)
                    native_reads.append(count)
                    return {"requests": count, "connection": "native"}
                lab.progress = progress
                class Peers:
                    client = "198.18.0.9"
                    reads = []
                    values = iter([3, 10, 10, 14])
                    def preflight(self): pass
                    def start(self, target): pass
                    def close(self): pass
                    def progress(self):
                        count = next(self.values)
                        self.reads.append(count)
                        return [{"requests": count, "connection": ("reconnected" if reconnect and count == 14 else str(i))} for i in range(2)]
                lab.external = Peers()
                def wait(predicate, *args):
                    for _ in range(8):
                        result = predicate()
                        if result: return result
                    raise RuntimeError("mock wait exhausted")
                lab.wait = wait
                process = Mock()
                process.poll.return_value = None
                with patch.object(validate.subprocess, "Popen", return_value=process):
                    if reconnect:
                        with self.assertRaisesRegex(RuntimeError, "reconnected"):
                            lab.validate()
                    else:
                        lab.validate()
                        self.assertEqual(lab.verify_external.call_count, 3)
                self.assertEqual(native_reads, [3, 10, 10, 14])
                self.assertEqual(lab.external.reads, [3, 10, 10, 14])


if __name__ == "__main__":
    unittest.main()
