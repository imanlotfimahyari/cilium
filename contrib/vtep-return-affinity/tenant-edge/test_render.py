# This file was not reviewed by a human before submission
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium
import json
from pathlib import Path
import unittest

from render import render, unique_keys


EXAMPLE = Path(__file__).with_name("tenants.example.json")


class TenantFrontendTests(unittest.TestCase):
    def setUp(self):
        self.tenants = json.loads(EXAMPLE.read_text())["tenants"]

    def test_overlapping_ingress_keeps_separate_backend_paths(self):
        a, b = render(self.tenants).values()
        for config, tenant in zip((a, b), self.tenants):
            self.assertIn("bind 198.18.0.1:8080", config)
            self.assertIn(f"source {tenant['egress_ip']}", config)
            self.assertIn(f"server backend {tenant['backend_ip']}:18080", config)
            self.assertNotIn("send-proxy", config)
        self.assertNotIn(self.tenants[1]["backend_ip"], a)
        self.assertNotIn(self.tenants[0]["backend_ip"], b)

    def test_rejects_shared_or_ambiguous_backend_addresses(self):
        for values in ({"backend_ip": self.tenants[0]["backend_ip"]},
                       {"egress_ip": self.tenants[0]["backend_ip"]},
                       {"egress_ip": self.tenants[0]["egress_ip"]},
                       {"backend_ip": "198.18.0.25"}):
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    render([self.tenants[0], self.tenants[1] | values])

    def test_invalid_inputs_fail_closed(self):
        for values in ({"name": "../another-file"}, {"name": "tenant-a"},
                       {"listen_port": True}, {"listen_port": 65536},
                       {"listen_ip": "198.19.0.1"}, {"listen_ip": "0.0.0.0"},
                       {"backend_ip": "192.0.2.10\n    server unexpected"},
                       {"extra": 1}):
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    render([self.tenants[0], self.tenants[1] | values])

    def test_rejects_duplicate_json_fields(self):
        with self.assertRaises(ValueError):
            json.loads('{"name": "tenant-a", "name": "tenant-b"}',
                       object_pairs_hook=unique_keys)


if __name__ == "__main__":
    unittest.main()
