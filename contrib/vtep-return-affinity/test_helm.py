# This file was not reviewed by a human before submission
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium
"""Render tests for the fork-only default-off experiment; no cluster access."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "install/kubernetes/cilium"
FLAG = "enable-experimental-vtep-return-affinity"
BASELINE = "14a657076fc1e4eb176e272c8d7246851283692f"


class HelmAffinityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helm = os.environ.get("VTEP_HELM_BINARY") or shutil.which("helm")
        if not cls.helm:
            raise unittest.SkipTest("set VTEP_HELM_BINARY to execute chart render tests")

    def render(self, overrides=None, chart=CHART, config_only=True, check=True):
        with tempfile.TemporaryDirectory() as directory:
            values = Path(directory)/"values.json"
            values.write_text(json.dumps(overrides or {}))
            cmd = [self.helm, "template", "affinity-lab", str(chart), "--namespace", "kube-system", "--kube-version", "1.35.0", "--values", str(values)]
            if config_only:
                cmd += ["--show-only", "templates/cilium-configmap.yaml"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
            if check:
                self.assertEqual(result.returncode, 0, result.stderr)
            return result

    def enabled(self):
        return {"vtep": {"enabled": True, "experimentalReturnAffinity": {"enabled": True},
                         "endpoint": "192.0.2.10", "mac": "02:00:00:00:00:10",
                         "cidr": "198.18.0.0/24", "mask": "255.255.255.0"},
                "l7Proxy": False, "kubeProxyReplacement": True}

    def test_default_config_and_deterministic_resources_match_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            baseline = Path(directory)/"chart"
            shutil.copytree(CHART, baseline)
            for path in ["values.yaml", "values.schema.json", "templates/validate.yaml", "templates/cilium-configmap.yaml"]:
                original = subprocess.check_output(["git", "show", BASELINE+":install/kubernetes/cilium/"+path], cwd=ROOT)
                (baseline/path).write_bytes(original)
            self.assertEqual(self.render(chart=baseline).stdout, self.render().stdout)
            def stable(text):
                result = []
                for item in yaml.safe_load_all(text):
                    if not item:
                        continue
                    # Upstream explicitly identifies generated TLS secrets.
                    metadata = item.get("metadata", {})
                    markers = dict(metadata.get("labels") or {}, **(metadata.get("annotations") or {}))
                    if "cilium.io/helm-template-non-idempotent" not in markers:
                        result.append(item)
                return result
            self.assertEqual(stable(self.render(chart=baseline, config_only=False).stdout), stable(self.render(config_only=False).stdout))
        self.assertNotIn(FLAG, yaml.safe_load(self.render().stdout)["data"])

    def test_enabled_flag_is_unique_and_remains_a_string(self):
        text = self.render(self.enabled()).stdout
        self.assertEqual(text.count(FLAG+":"), 1)
        self.assertEqual(yaml.safe_load(text)["data"][FLAG], "true")

    def test_unsupported_combinations_fail_before_installation(self):
        cases = [("vtep", "enabled", False), ("ipv4", "enabled", False), ("ipv6", "enabled", True),
                 (None, "routingMode", "native"), (None, "tunnelProtocol", "geneve"),
                 (None, "underlayProtocol", "ipv6"), ("bpf", "datapathMode", "netkit"),
                 ("bpf", "enableTCX", False), ("bpf", "hostLegacyRouting", True),
                 (None, "kubeProxyReplacement", False), (None, "l7Proxy", True),
                 ("endpointRoutes", "enabled", True), ("encryption", "enabled", True),
                 (None, "cleanState", True), (None, "cleanBpfState", True),
                 ("vtep", "endpoint", ""), ("vtep", "mac", ""), ("vtep", "cidr", ""), ("vtep", "mask", "")]
        for parent, key, value in cases:
            with self.subTest(option=(parent, key)):
                values = self.enabled()
                if parent:
                    values.setdefault(parent, {})[key] = value
                else:
                    values[key] = value
                result = self.render(values, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("experimentalReturnAffinity", result.stderr)

    def test_schema_rejects_string_boolean(self):
        values = self.enabled()
        values["vtep"]["experimentalReturnAffinity"]["enabled"] = "true"
        result = self.render(values, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("boolean", result.stderr)

    def test_duplicate_extra_config_is_rejected_and_legacy_path_preserved(self):
        values = self.enabled()
        values["extraConfig"] = {FLAG: "true"}
        self.assertNotEqual(self.render(values, check=False).returncode, 0)
        values["vtep"]["experimentalReturnAffinity"]["enabled"] = False
        text = self.render(values).stdout
        self.assertEqual(text.count(FLAG+":"), 1)
        self.assertEqual(yaml.safe_load(text)["data"][FLAG], "true")

    def test_eks_example_preserves_images_api_and_networking(self):
        values = yaml.safe_load((CHART/"examples/values-eks-vtep-affinity.yaml").read_text())
        values["k8sServiceHost"] = "api.example.com"
        values["ipam"]["operator"]["clusterPoolIPv4PodCIDRList"] = ["10.240.0.0/16"]
        values["image"]["override"] = "registry.example.com/lab/cilium:source-checkpoint"
        values["operator"]["image"]["override"] = "registry.example.com/lab/operator-generic:source-checkpoint"
        docs = [d for d in yaml.safe_load_all(self.render(values, config_only=False).stdout) if d]
        config = next(d["data"] for d in docs if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "cilium-config")
        for key, value in {"ipam": "cluster-pool", "kube-proxy-replacement": "true",
                           "routing-mode": "tunnel", "tunnel-protocol": "vxlan",
                           "enable-ipv4": "true", "enable-ipv6": "false",
                           "enable-tcx": "true", "enable-host-legacy-routing": "false",
                           "enable-bpf-masquerade": "true", "cni-exclusive": "true",
                           "enable-l7-proxy": "false"}.items():
            self.assertEqual(config[key], value, key)
        self.assertNotIn(FLAG, config)
        for kind, name, container, image in [
                ("DaemonSet", "cilium", "cilium-agent", values["image"]["override"]),
                ("Deployment", "cilium-operator", "cilium-operator", values["operator"]["image"]["override"])]:
            workload = next(d for d in docs if d["kind"] == kind and d["metadata"]["name"] == name)
            spec = workload["spec"]["template"]["spec"]
            self.assertTrue(spec["hostNetwork"])
            actual = next(c for c in spec["containers"] if c["name"] == container)
            self.assertEqual(actual["image"], image)
            env = {e["name"]: e.get("value") for e in actual["env"]}
            self.assertEqual(env["KUBERNETES_SERVICE_HOST"], "api.example.com")
            self.assertEqual(env["KUBERNETES_SERVICE_PORT"], "443")
        values["vtep"] = self.enabled()["vtep"]
        self.assertEqual(yaml.safe_load(self.render(values).stdout)["data"][FLAG], "true")

    def test_package_includes_full_values_and_install_examples(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([self.helm, "package", str(CHART), "--destination", directory],
                                    capture_output=True, text=True, timeout=45)
            self.assertEqual(result.returncode, 0, result.stderr)
            packages = list(Path(directory).glob("cilium-*.tgz"))
            self.assertEqual(len(packages), 1)
            with tarfile.open(packages[0]) as package:
                for path in ["values.yaml", "values.schema.json", "examples/values-eks-vtep-affinity.yaml",
                             "examples/INSTALL-VTEP.md"]:
                    self.assertEqual(package.extractfile("cilium/"+path).read(), (CHART/path).read_bytes(), path)


if __name__ == "__main__":
    unittest.main()
