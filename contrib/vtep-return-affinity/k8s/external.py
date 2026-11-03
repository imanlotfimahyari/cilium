# This file was not reviewed by a human before submission
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium
"""Optional external VXLAN clients in two operator-provisioned Docker containers.

Only an explicitly labelled, local disposable fixture is modified. No node
routes, Cilium configuration, existing links or container lifecycle are changed.
"""
import ipaddress
import json
import os
import re
import subprocess

LABEL = "vtep-return-affinity.cilium.io/peer"
LINK = "akvtep"


def peer_metadata(items, network):
    if len(items) != 2:
        raise ValueError("exactly two external peer containers are required")
    peers = []
    for item in items:
        if not item.get("State", {}).get("Running") or item.get("Config", {}).get("Labels", {}).get(LABEL) != "true":
            raise ValueError("external peers must be running explicitly labelled lab containers")
        networks = item.get("NetworkSettings", {}).get("Networks", {})
        if set(networks) != {network} or item.get("HostConfig", {}).get("NetworkMode") != network:
            raise ValueError("external peers need exactly the dedicated kind bridge network")
        endpoint = networks[network]
        address = ipaddress.IPv4Address(endpoint["IPAddress"])
        mac = endpoint["MacAddress"].lower()
        if address.is_multicast or address.is_unspecified or address.is_loopback or not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac):
            raise ValueError("invalid external peer network identity")
        if int(mac[:2], 16) & 1:
            raise ValueError("external peer MAC must be unicast")
        peers.append({"id": item["Id"], "address": str(address), "mac": mac})
    if len({p["id"] for p in peers}) != 2 or len({p["address"] for p in peers}) != 2 or len({p["mac"] for p in peers}) != 2:
        raise ValueError("external peer identities must be distinct")
    return peers


class ExternalPeers:
    def __init__(self, names, network, client):
        if len(names) != 2 or len(set(names)) != 2 or any(not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}", n) for n in names):
            raise ValueError("supply two distinct explicit peer container names")
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}", network):
            raise ValueError("invalid Docker lab network name")
        address = ipaddress.IPv4Interface(client)
        if address.network.prefixlen != 32 or address.ip not in ipaddress.IPv4Network("198.18.0.0/15"):
            raise ValueError("external client must be a /32 from the isolated benchmarking range")
        self.names, self.network, self.client = names, network, str(address.ip)
        self.peers, self.created, self.holds = [], [], []
        self.state = "/tmp/affinity-external-" + os.urandom(8).hex() + ".json"

    def docker(self, *args, check=True):
        result = subprocess.run(["docker", *args], text=True, capture_output=True, timeout=30)
        if check and result.returncode:
            raise RuntimeError("external peer Docker operation failed")
        return result

    def execute(self, peer, *args, check=True):
        return self.docker("exec", peer["id"], *args, check=check)

    def preflight(self):
        if os.environ.get("DOCKER_HOST") or os.environ.get("DOCKER_CONTEXT") or self.docker("context", "show").stdout.strip() != "default":
            raise RuntimeError("external fixture requires the local default Docker context")
        context = json.loads(self.docker("context", "inspect", "default").stdout)
        if len(context) != 1 or not context[0].get("Endpoints", {}).get("docker", {}).get("Host", "").startswith("unix://"):
            raise RuntimeError("remote Docker endpoints are not supported")
        self.peers = peer_metadata(json.loads(self.docker("inspect", *self.names).stdout), self.network)
        for peer in self.peers:
            self.execute(peer, "ip", "-j", "link", "show", "dev", "eth0")
            self.execute(peer, "/affinity-probe", "-h")
            existing = self.execute(peer, "ip", "-j", "link", "show", check=True)
            if any(link.get("ifname") == LINK for link in json.loads(existing.stdout)):
                raise RuntimeError("external fixture link already exists; refusing to adopt or replace it")

    def configure(self, target, node, node_mac):
        target, node = str(ipaddress.IPv4Address(target)), str(ipaddress.IPv4Address(node))
        if not re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", node_mac):
            raise ValueError("invalid node VXLAN MAC")
        for peer in self.peers:
            if peer not in self.created:
                self.execute(peer, "ip", "link", "add", LINK, "type", "vxlan", "id", "2", "local", peer["address"], "remote", node,
                             "dev", "eth0", "dstport", "8472", "nolearning")
                self.created.append(peer)  # Cleanup also covers later setup failures.
                self.execute(peer, "ip", "link", "set", "dev", LINK, "address", peer["mac"])
                self.execute(peer, "ip", "addr", "add", self.client + "/32", "dev", LINK)
                self.execute(peer, "ip", "link", "set", LINK, "up")
            else:
                self.execute(peer, "ip", "link", "set", LINK, "type", "vxlan", "remote", node)
                # A replaced workload must not leave an old destination route.
                self.execute(peer, "ip", "route", "flush", "dev", LINK)
                self.execute(peer, "ip", "neigh", "flush", "dev", LINK)
            self.execute(peer, "ip", "route", "add", target + "/32", "dev", LINK)
            self.execute(peer, "ip", "neigh", "replace", target, "lladdr", node_mac, "nud", "permanent", "dev", LINK)

    def request(self, peer, target, port):
        result = self.execute(peer, "/affinity-probe", "-mode=request", "-target="+target,
                              "-source="+self.client+":"+str(port), "-timeout=2s", check=False)
        if result.returncode == 0 and result.stdout.strip() == "PASS":
            return True
        if result.returncode != 0 and result.stderr.strip() == "TCP connection failed":
            return False
        raise RuntimeError("external probe execution failed independently of policy")

    def start(self, target):
        for i, peer in enumerate(self.peers):
            process = subprocess.Popen(["docker", "exec", peer["id"], "/affinity-probe", "-mode=hold", "-target="+target,
                                        "-source="+self.client+":"+str(49000+i), "-state="+self.state, "-timeout=5s"],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.holds.append(process)

    def progress(self):
        result = []
        for peer, process in zip(self.peers, self.holds):
            if process.poll() is not None:
                raise RuntimeError("external persistent TCP process exited")
            state = self.execute(peer, "/affinity-probe", "-mode=read-state", "-state="+self.state, check=False)
            if state.returncode:
                return None
            record = json.loads(state.stdout)
            if record.get("error"):
                raise RuntimeError("external persistent TCP connection failed")
            if record.get("requests", 0) < 3:
                return None
            result.append(record)
        return result if len(result) == 2 else None

    def close(self):
        errors = []
        # Removing only the links created by this run makes remote hold sockets
        # fail their bounded deadline too; terminating docker alone would not.
        for peer in self.created:
            try:
                result = self.execute(peer, "ip", "link", "del", LINK, check=False)
                if result.returncode:
                    errors.append("external link cleanup")
            except (RuntimeError, subprocess.TimeoutExpired):
                errors.append("external link cleanup")
        for process in self.holds:
            try:
                process.wait(timeout=7)
            except subprocess.TimeoutExpired:
                errors.append("external process cleanup")
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
        for peer in self.created:
            try:
                result = self.execute(peer, "rm", "-f", self.state, self.state+".tmp", check=False)
                if result.returncode:
                    errors.append("external state cleanup")
            except (RuntimeError, subprocess.TimeoutExpired):
                errors.append("external state cleanup")
        self.created.clear()
        self.holds.clear()
        if errors:
            raise RuntimeError("external fixture cleanup incomplete")
