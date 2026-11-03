# This file was not reviewed by a human before submission
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium
import copy
import json
import subprocess
import unittest
from unittest.mock import patch

from external import ExternalPeers, peer_metadata


def metadata():
    return [{"Id": "peer"+str(i), "State": {"Running": True},
             "Config": {"Labels": {"vtep-return-affinity.cilium.io/peer": "true"}},
             "HostConfig": {"NetworkMode": "kind"}, "NetworkSettings": {"Networks": {"kind": {
                 "IPAddress": "192.0.2."+str(i+10), "MacAddress": "02:00:00:00:00:0"+str(i)}}}} for i in (1, 2)]


class ExternalSafetyTests(unittest.TestCase):
    def test_requires_explicit_distinct_isolated_peers(self):
        self.assertEqual(len(peer_metadata(metadata(), "kind")), 2)
        for mutate in (lambda m: m[0]["Config"]["Labels"].clear(),
                       lambda m: m[0]["State"].update(Running=False),
                       lambda m: m[0]["HostConfig"].update(NetworkMode="host"),
                       lambda m: m[0]["HostConfig"].update(NetworkMode="container:node"),
                       lambda m: m[1].update(Id=m[0]["Id"]),
                       lambda m: m[1]["NetworkSettings"]["Networks"]["kind"].update(IPAddress="192.0.2.11")):
            with self.subTest(mutate=mutate):
                items = metadata()
                mutate(items)
                with self.assertRaises(ValueError):
                    peer_metadata(items, "kind")

    def test_bad_names_and_client_ranges_fail_before_docker(self):
        for names, client in ((["--host", "peer"], "198.18.0.9/32"), (["peer", "peer"], "198.18.0.9/32"),
                              (["a", "b"], "198.18.0.9/24"), (["a", "b"], "192.0.2.1/32")):
            with self.assertRaises(ValueError):
                ExternalPeers(names, "kind", client)

    def test_refuses_existing_link_before_any_mutation(self):
        peers = ExternalPeers(["a", "b"], "kind", "198.18.0.9/32")
        mutations = []
        def docker(*args, **kwargs):
            if args == ("context", "show"): output = "default"
            elif args == ("context", "inspect", "default"): output = json.dumps([{"Endpoints": {"docker": {"Host": "unix:///var/run/docker.sock"}}}])
            elif args[0] == "inspect": output = json.dumps(metadata())
            elif args[-3:] == ("-j", "link", "show"): output = '[{"ifname":"akvtep"}]'
            else: output = "[]"
            mutations.append(args)
            return subprocess.CompletedProcess([], 0, output, "")
        peers.docker = docker
        with patch.dict("os.environ", {}, clear=True), self.assertRaises(RuntimeError):
            peers.preflight()
        self.assertFalse(any("add" in command or "del" in command for command in mutations))
        self.assertEqual(peers.created, [])

    def test_failed_exec_is_not_policy_denial(self):
        peers = ExternalPeers(["a", "b"], "kind", "198.18.0.9/32")
        peers.execute = lambda *a, **k: subprocess.CompletedProcess([], 1, "", "container stopped")
        with self.assertRaises(RuntimeError): peers.request({}, "192.0.2.2:8080", 51000)
        peers.execute = lambda *a, **k: subprocess.CompletedProcess([], 1, "", "TCP connection failed\n")
        self.assertFalse(peers.request({}, "192.0.2.2:8080", 51001))

    def test_partial_setup_and_cleanup_failure_still_attempts_both_peers(self):
        peers = ExternalPeers(["a", "b"], "kind", "198.18.0.9/32")
        peers.peers = peer_metadata(metadata(), "kind")
        attempts = []
        def execute(peer, *args, **kwargs):
            attempts.append((peer["id"], args))
            if args[:3] == ("ip", "link", "del") and peer["id"] == "peer1":
                raise subprocess.TimeoutExpired("docker", 30)
            return subprocess.CompletedProcess([], 0, "", "")
        peers.execute = execute
        peers.created = copy.copy(peers.peers)
        with self.assertRaises(RuntimeError): peers.close()
        self.assertEqual(sum(args[:3] == ("ip", "link", "del") for _, args in attempts), 2)


if __name__ == "__main__": unittest.main()
