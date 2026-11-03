#!/usr/bin/env python3
# This file was not reviewed by a human before submission
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium
"""Validate native IPv4 TCP and actual CNI/identity/policy/lifecycle in a disposable lab.

The patched Cilium installation and workload image must already be available.
Optional explicitly labelled Docker peers add external VNI-2 VXLAN coverage.
No default context, kubeconfig contents, secrets, node addresses or raw logs are exported.
"""
import argparse
import json
import ipaddress
from pathlib import Path
import re
import shutil
import subprocess
import time
import uuid
from external import ExternalPeers

LAB_LABEL = "vtep-return-affinity.cilium.io/lab"


def context_guard(context):
    if not re.fullmatch(r"kind-vtep-affinity-lab(?:-[a-z0-9-]+)?", context):
        raise ValueError("use an explicitly named kind-vtep-affinity-lab context")


def endpoint_for(endpoints, namespace, pod):
    for endpoint in endpoints:
        status = endpoint.get("status", {})
        external = status.get("external-identifiers", {})
        if external.get("pod-name") == f"{namespace}/{pod}" or (
            external.get("k8s-namespace") == namespace and external.get("k8s-pod-name") == pod
        ):
            return endpoint
    return None


class Lab:
    def __init__(self, args):
        context_guard(args.context)
        self.args = args
        self.ns = "vtep-affinity-" + uuid.uuid4().hex[:10]
        self.prefix = ["kubectl", "--context", args.context, "--request-timeout=30s"]
        self.records = []
        self.created = False
        self.hold = None
        self.cordoned = None
        self.server_uid = None
        self.external = (ExternalPeers(args.external_peer, args.external_network, args.external_client)
                         if getattr(args, "external_peer", None) else None)
        self.external_port = 51000

    def run(self, *args, check=True, data=None, timeout=90):
        result = subprocess.run(self.prefix + list(args), input=data, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        if check and result.returncode:
            # API errors can contain addresses/paths. Keep them out of the report.
            raise RuntimeError("kubectl operation failed: " + " ".join(args[:2]))
        return result

    def get(self, *args):
        return json.loads(self.run("get", *args, "-o", "json").stdout)

    def apply(self, obj):
        self.run("apply", "-f", "-", data=json.dumps(obj))

    def wait(self, predicate, description, seconds=240):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                value = predicate()
                if value:
                    return value
            except (RuntimeError, KeyError, ValueError, subprocess.TimeoutExpired):
                pass
            time.sleep(1)
        raise RuntimeError("timed out: " + description)

    def record(self, name):
        self.records.append({"check": name, "status": "passed"})
        print("PASS " + name, flush=True)

    def agent(self, node, previous_uid=None):
        for pod in self.get("pods", "-n", self.args.cilium_namespace, "-l", "k8s-app=cilium")["items"]:
            ready = any(c.get("type") == "Ready" and c.get("status") == "True"
                        for c in pod.get("status", {}).get("conditions", []))
            if pod["spec"].get("nodeName") == node and ready and not pod["metadata"].get("deletionTimestamp"):
                if previous_uid != pod["metadata"]["uid"]:
                    return pod
        return None

    def server(self, previous_uid=None, different_node=None):
        for pod in self.get("pods", "-n", self.ns, "-l", "role=server")["items"]:
            ready = any(c.get("type") == "Ready" and c.get("status") == "True"
                        for c in pod.get("status", {}).get("conditions", []))
            if (ready and not pod["metadata"].get("deletionTimestamp") and pod["status"].get("podIP")
                    and pod["metadata"]["uid"] != previous_uid and pod["spec"].get("nodeName") != different_node):
                return pod
        return None

    def selected_endpoint(self, pod):
        agent = self.wait(lambda: self.agent(pod["spec"]["nodeName"]), "agent readiness")
        name = agent["metadata"]["name"]
        ep = self.wait(lambda: endpoint_for(json.loads(self.run(
            "exec", "-n", self.args.cilium_namespace, name, "-c", "cilium-agent", "--",
            "cilium-dbg", "endpoint", "list", "-o", "json").stdout), self.ns, pod["metadata"]["name"]),
            "Cilium endpoint creation")
        if ep["status"].get("state") != "ready":
            raise RuntimeError("Cilium endpoint is not ready")
        if int(ep["status"].get("identity", {}).get("id", 0)) < 256:
            raise RuntimeError("endpoint has a reserved/no-policy identity")
        header = self.run("exec", "-n", self.args.cilium_namespace, name, "-c", "cilium-agent", "--",
                          "cat", f"/var/run/cilium/state/{ep['id']}/ep_config.h").stdout
        if not re.search(r"^#define ENABLE_VTEP_RETURN_SOCKET_AFFINITY\s+1\s*$", header, re.M):
            raise RuntimeError("actual CNI endpoint did not opt into affinity")
        return ep

    def client_pod(self, role):
        def ready_client():
            for p in self.get("pods", "-n", self.ns, "-l", "role="+role)["items"]:
                if not p["metadata"].get("deletionTimestamp") and any(c.get("type") == "Ready" and c.get("status") == "True" for c in p.get("status", {}).get("conditions", [])):
                    return p
            return None
        return self.wait(ready_client, "client readiness")

    def request(self, client, target):
        result = self.run("exec", "-n", self.ns, self.client_pod(client)["metadata"]["name"], "--", "/affinity-probe", "-mode=request",
                          "-target=" + target, "-timeout=2s", check=False, timeout=15)
        if result.returncode == 0 and result.stdout.strip() == "PASS":
            return True
        if result.returncode != 0 and "TCP connection failed" in result.stderr:
            return False
        raise RuntimeError("probe execution failed independently of TCP policy")

    def verify_policy(self, server):
        target = server["status"]["podIP"] + ":8080"
        self.wait(lambda: self.request("allowed", target), "allowed direct-pod traffic")
        # Also prove the denied pod can execute the probe, avoiding false passes
        # caused by a missing executable, Pending pod or failed exec transport.
        self.run("exec", "-n", self.ns, self.client_pod("denied")["metadata"]["name"], "--", "/affinity-probe", "-h")
        failures = 0
        def denied():
            nonlocal failures
            failures = failures + 1 if not self.request("denied", target) else 0
            return failures >= 3
        self.wait(denied, "ingress policy enforcement")
        return target

    def deploy(self, nodes):
        self.run("create", "namespace", self.ns)
        self.created = True
        security = {"runAsNonRoot": True, "runAsUser": 65532, "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
        base = {"name": "probe", "image": self.args.image, "imagePullPolicy": "IfNotPresent",
                "securityContext": security, "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                "limits": {"cpu": "100m", "memory": "64Mi"}}}
        workload = dict(base, args=["-mode=serve", "-target=:8080"],
                        readinessProbe={"tcpSocket": {"port": 8080}, "periodSeconds": 1})
        self.apply({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "server", "namespace": self.ns},
                    "spec": {"replicas": 1, "selector": {"matchLabels": {"role": "server"}},
                    "template": {"metadata": {"labels": {"role": "server"}}, "spec": {
                        "automountServiceAccountToken": False, "nodeSelector": {LAB_LABEL: "true"}, "containers": [workload]}}}})
        server = self.wait(lambda: self.server(), "server scheduling and CNI", 300)
        other = next(n for n in nodes if n != server["spec"]["nodeName"])
        for role in ("allowed", "denied"):
            # A local listener keeps the client pod alive without a shell/base OS.
            container = dict(base, args=["-mode=serve", "-target=:9090"],
                             volumeMounts=[{"name": "tmp", "mountPath": "/tmp"}])
            self.apply({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": role, "namespace": self.ns},
                        "spec": {"replicas": 1, "selector": {"matchLabels": {"role": role}}, "template": {
                            "metadata": {"labels": {"role": role}}, "spec": {"nodeSelector": {LAB_LABEL: "true"},
                            "affinity": {"nodeAffinity": {"preferredDuringSchedulingIgnoredDuringExecution": [{"weight": 100,
                                "preference": {"matchExpressions": [{"key": "kubernetes.io/hostname", "operator": "In", "values": [other]}]}}]}},
                            "automountServiceAccountToken": False, "securityContext": {"fsGroup": 65532},
                            "containers": [container], "volumes": [{"name": "tmp", "emptyDir": {}}]}}}})
            pod = self.client_pod(role)
            if pod["spec"]["nodeName"] == server["spec"]["nodeName"]:
                raise RuntimeError("initial clients must schedule on a different node for cross-node coverage")
        self.apply({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                    "metadata": {"name": "server-ingress", "namespace": self.ns}, "spec": {
                        "podSelector": {"matchLabels": {"role": "server"}}, "policyTypes": ["Ingress"],
                        "ingress": [{"from": [{"podSelector": {"matchLabels": {"role": "allowed"}}}],
                                     "ports": [{"protocol": "TCP", "port": 8080}]}]}})
        return server

    def progress(self):
        result = self.run("exec", "-n", self.ns, self.client_pod("allowed")["metadata"]["name"], "--", "/affinity-probe", "-mode=read-state", check=False)
        if result.returncode:
            return None
        p = json.loads(result.stdout)
        if p.get("error"):
            raise RuntimeError("existing TCP connection failed during agent restart")
        return p if p.get("requests", 0) >= 3 else None

    def external_request(self, peer, target):
        # Never reuse a tuple across policy/endpoint transitions or retries.
        self.external_port += 1
        if self.external_port >= 65000:
            raise RuntimeError("external fresh-tuple probe budget exhausted")
        return self.external.request(peer, target, self.external_port)

    def verify_external(self, server):
        node = self.get("node", server["spec"]["nodeName"])
        address = next(a["address"] for a in node["status"]["addresses"] if a["type"] == "InternalIP" and ":" not in a["address"])
        agent = self.wait(lambda: self.agent(server["spec"]["nodeName"]), "external target agent")
        mac = self.run("exec", "-n", self.args.cilium_namespace, agent["metadata"]["name"], "-c", "cilium-agent", "--",
                       "cat", "/sys/class/net/cilium_vxlan/address").stdout.strip()
        target = server["status"]["podIP"] + ":8080"
        self.external.configure(server["status"]["podIP"], address, mac)
        policy = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": "external-clients", "namespace": self.ns},
                  "spec": {"podSelector": {"matchLabels": {"role": "server"}}, "policyTypes": ["Ingress"], "ingress": [
                      {"from": [{"ipBlock": {"cidr": self.external.client+"/32"}}], "ports": [{"protocol": "TCP", "port": 8080}]}]}}
        self.apply(policy)
        for peer in self.external.peers:
            self.wait(lambda: self.external_request(peer, target), "external VXLAN allowed traffic")
        # Prove reachability first; failed exec/setup cannot count as denial.
        self.run("delete", "networkpolicy", "external-clients", "-n", self.ns)
        for peer in self.external.peers:
            failures = 0
            def denied():
                nonlocal failures
                failures = failures + 1 if not self.external_request(peer, target) else 0
                return failures >= 3
            self.wait(denied, "external VXLAN policy denial")
        self.apply(policy)
        for peer in self.external.peers:
            self.wait(lambda: self.external_request(peer, target), "external VXLAN policy restoration")
        self.verify_policy(server)
        self.record("two external VXLAN peers with a shared client address obey allow/deny policy")
        return target

    def validate(self):
        nodes = self.get("nodes")["items"]
        # Every node must carry explicit disposable-lab ownership. Never mutate
        # a mixed/production cluster simply because its context was renamed.
        if len(nodes) < 2 or any(n["metadata"].get("labels", {}).get(LAB_LABEL) != "true" for n in nodes):
            raise RuntimeError("all nodes must be explicitly labelled as a disposable affinity lab; need >=2 nodes")
        schedulable = [n["metadata"]["name"] for n in nodes if not n["spec"].get("unschedulable")
                       and not any(t.get("effect") in ("NoSchedule", "NoExecute") for t in n["spec"].get("taints", []))]
        if len(schedulable) < 2:
            raise RuntimeError("need two schedulable, untainted lab nodes")
        if self.external:
            client = ipaddress.IPv4Address(self.external.client)
            for node in nodes:
                cidrs = node.get("spec", {}).get("podCIDRs", []) + ([node["spec"]["podCIDR"]] if node.get("spec", {}).get("podCIDR") else [])
                if any(client.version == (network := ipaddress.ip_network(cidr)).version and client in network for cidr in cidrs):
                    raise RuntimeError("external client overlaps a node pod range")
                if any(a.get("address") == self.external.client for a in node.get("status", {}).get("addresses", [])):
                    raise RuntimeError("external client overlaps a node address")
        self.record("explicit disposable-cluster preflight")
        if self.external:
            self.external.preflight()
        server = self.deploy(schedulable)
        self.selected_endpoint(server)
        for role in ("allowed", "denied"):
            self.selected_endpoint(self.client_pod(role))
        target = self.verify_policy(server)
        self.record("actual CNI selection, normal identities and cross-node allow/deny policy")
        if self.external:
            external_target = self.verify_external(server)
        if self.args.restart_agent:
            self.hold = subprocess.Popen(self.prefix + ["exec", "-n", self.ns, self.client_pod("allowed")["metadata"]["name"], "--", "/affinity-probe",
                                                        "-mode=hold", "-target="+target, "-timeout=5s"],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            before = self.wait(self.progress, "persistent connection start")
            if self.external:
                self.external.start(external_target)
                external_before = self.wait(self.external.progress, "both external persistent connections")
            node = server["spec"]["nodeName"]
            old = self.agent(node)
            self.run("delete", "pod", "-n", self.args.cilium_namespace, old["metadata"]["name"], "--wait=false")
            self.wait(lambda: self.agent(node, old["metadata"]["uid"]), "replacement agent readiness", 600)
            self.wait(lambda: self.selected_endpoint(server), "restored selected endpoint", 300)
            # Require fresh progress after readiness, not a stale state file
            # written while the agent was down or still restoring endpoints.
            restored = self.wait(self.progress, "post-restore TCP checkpoint")
            external_restored = self.wait(self.external.progress, "post-restore external checkpoints") if self.external else None
            after = self.wait(lambda: (p if (p := self.progress()) and p["requests"] > restored["requests"]+3 else None), "existing TCP progress after restore")
            if after["connection"] != before["connection"] or self.hold.poll() is not None:
                raise RuntimeError("agent restart did not preserve the same TCP connection")
            self.verify_policy(server)
            self.record("real agent pod replacement preserves existing TCP connection and policy")
            if self.external:
                def external_progress():
                    records = self.external.progress()
                    if not records or any(p["requests"] <= b["requests"]+3 for p, b in zip(records, external_restored)):
                        return None
                    if any(p["connection"] != b["connection"] for p, b in zip(records, external_before)):
                        raise RuntimeError("external connection reconnected during agent restart")
                    return records
                self.wait(external_progress, "both external TCP connections survive agent restart")
                self.record("agent restart preserves simultaneous external-peer TCP connections without reconnect")
                self.external.close()
                self.verify_external(server)
        previous = server["metadata"]["uid"]
        self.run("delete", "pod", "-n", self.ns, server["metadata"]["name"], "--wait=false")
        server = self.wait(lambda: self.server(previous_uid=previous), "replacement workload pod", 300)
        self.selected_endpoint(server)
        self.verify_policy(server)
        self.record("workload replacement receives a new CNI endpoint and retains policy")
        if self.external:
            self.verify_external(server)
        if self.args.drain_node:
            self.cordoned = server["spec"]["nodeName"]
            previous = server["metadata"]["uid"]
            self.run("drain", self.cordoned, "--ignore-daemonsets", "--delete-emptydir-data", "--timeout=300s", timeout=320)
            server = self.wait(lambda: self.server(previous, self.cordoned), "rescheduling after node drain", 300)
            self.selected_endpoint(server)
            self.verify_policy(server)
            self.record("node drain reschedules workload with working CNI and policy")
            if self.external:
                self.verify_external(server)
                self.record("external VXLAN policy and fresh connections work after node drain")

    def close(self):
        errors = []
        if self.external:
            try:
                self.external.close()
            except (RuntimeError, subprocess.TimeoutExpired):
                errors.append("external fixture cleanup")
        if self.hold is not None:
            self.hold.terminate()
            try:
                self.hold.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.hold.kill()
                self.hold.wait(timeout=10)
        if self.created:
            try:
                self.run("delete", "namespace", self.ns, "--wait=true", "--timeout=120s", timeout=140)
            except (RuntimeError, subprocess.TimeoutExpired):
                errors.append("namespace cleanup")
        if self.cordoned:
            try:
                self.run("uncordon", self.cordoned)
            except (RuntimeError, subprocess.TimeoutExpired):
                errors.append("node uncordon")
        if errors:
            raise RuntimeError("lab cleanup incomplete: " + ", ".join(errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--image", required=True, help="preloaded image built with k8s/Dockerfile")
    parser.add_argument("--cilium-namespace", default="kube-system")
    parser.add_argument("--restart-agent", action="store_true", help="replace the server node's agent pod")
    parser.add_argument("--drain-node", action="store_true", help="drain and then uncordon the server's lab node")
    parser.add_argument("--external-peer", action="append", default=[], help="two preconfigured local Docker peer containers (repeat twice)")
    parser.add_argument("--external-network", default="kind", help="dedicated bridge shared by kind nodes and external peers")
    parser.add_argument("--external-client", default="198.18.0.9/32", help="shared isolated /32 client address; must not overlap cluster ranges")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    # A rejected invocation must not leave a previous run's PASS on disk.
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({"status": "blocked", "reason": "preflight not completed",
                                       "cluster_operations_performed": False, "checks": []}, indent=2)+"\n")
    try:
        context_guard(args.context)
        lab = Lab(args)
    except ValueError:
        parser.error("invalid disposable-lab arguments; no cluster operations were performed")
    missing = [name for name in (["kubectl", "docker"] if args.external_peer else ["kubectl"]) if not shutil.which(name)]
    if missing:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps({"status": "blocked", "reason": "required tools unavailable: " + ", ".join(missing),
                                           "cluster_operations_performed": False, "checks": []}, indent=2)+"\n")
        parser.error("required tools unavailable; no cluster operations were performed")
    result = {"scope": "native IPv4 TCP, real CNI/identity/policy/lifecycle", "external_peers_requested": bool(args.external_peer), "status": "failed"}
    try:
        lab.validate()
        result["status"] = "passed"
    finally:
        result["checks"] = lab.records
        try:
            lab.close()
        except (RuntimeError, subprocess.TimeoutExpired):
            result["status"] = "failed"
            result["cleanup"] = "incomplete"
            raise
        finally:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(result, indent=2)+"\n")


if __name__ == "__main__":
    main()
