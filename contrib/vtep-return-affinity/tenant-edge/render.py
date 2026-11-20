# This file was not reviewed by a human before submission
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium
"""Render one non-transparent HAProxy TCP frontend per tenant network namespace."""

import argparse
import ipaddress
import json
from pathlib import Path
import re


FIELDS = {"name", "ingress_cidr", "listen_ip", "listen_port",
          "egress_ip", "backend_ip", "backend_port"}


def address(value):
    if not isinstance(value, str):
        raise ValueError("IP addresses must be IPv4 strings")
    addr = ipaddress.IPv4Address(value)
    if addr.is_unspecified or addr.is_multicast or addr.is_loopback or addr.is_link_local or addr.is_reserved:
        raise ValueError("IP addresses must be routable within the intended network")
    return addr


def port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError("ports must be integers in 1..65535")
    return value


def render(tenants):
    if not isinstance(tenants, list) or len(tenants) < 2:
        raise ValueError("configure at least two tenants")
    configs = {}
    distinct = set()
    ingress_ranges = []
    uplink_addresses = []
    for item in tenants:
        if not isinstance(item, dict) or set(item) != FIELDS:
            raise ValueError("a tenant must define exactly the documented fields")
        name = item["name"]
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,39}", name):
            raise ValueError("tenant names must be lowercase and safe as filenames")
        if name in configs:
            raise ValueError("tenant names must be distinct")
        if not isinstance(item["ingress_cidr"], str):
            raise ValueError("ingress_cidr must be an IPv4 CIDR string")
        ingress = ipaddress.IPv4Network(item["ingress_cidr"])
        listener = address(item["listen_ip"])
        egress = address(item["egress_ip"])
        backend = address(item["backend_ip"])
        listen_port = port(item["listen_port"])
        backend_port = port(item["backend_port"])
        if listener not in ingress:
            raise ValueError("listener is outside its tenant ingress range")
        if egress == backend or egress in distinct or backend in distinct:
            raise ValueError("all egress and backend addresses must be distinct")
        distinct.update((egress, backend))
        ingress_ranges.append(ingress)
        uplink_addresses.extend((egress, backend))
        configs[name] = f"""# This file was not reviewed by a human before submission
# Install only in the dedicated network namespace for {name}.
global
    maxconn 1024

defaults
    mode tcp
    timeout connect 5s
    timeout client 60s
    timeout server 60s

frontend tenant_ingress
    bind {listener}:{listen_port}
    default_backend tenant_backend

backend tenant_backend
    source {egress}
    server backend {backend}:{backend_port}
"""
    if any(ip in network for ip in uplink_addresses for network in ingress_ranges):
        raise ValueError("egress and backend addresses must be outside every ingress range")
    return configs


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path, help="JSON tenant list")
    parser.add_argument("output", type=Path, help="new output directory")
    args = parser.parse_args()
    try:
        data = json.loads(args.config.read_text(), object_pairs_hook=unique_keys)
        if not isinstance(data, dict) or set(data) - {"_comment", "tenants"} or "tenants" not in data:
            raise ValueError("the input must contain a tenants array")
        configs = render(data["tenants"])
        args.output.mkdir(mode=0o700)
        for name, config in configs.items():
            with (args.output / (name + ".cfg")).open("x") as f:
                f.write(config)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Configuration not generated: {exc}\n")


if __name__ == "__main__":
    main()
