# This file was not reviewed by a human before submission
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium
"""Prove identical TCP tuples using isolated loopback namespaces and HAProxy."""

from contextlib import ExitStack
import fcntl
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile

from lab import BACKEND, HERE, REQUEST, SOURCE_PORT, stop, until
from render import render

CLIENT = "127.0.0.2"
LISTENER = "127.0.0.1"


def start(cleanup, args):
    process = subprocess.Popen(args)
    cleanup.callback(stop, process)
    return process


def worker(root, index, parent_netns):
    if os.readlink("/proc/self/ns/net") == parent_netns:
        raise RuntimeError("worker is not in a new network namespace")
    # iproute2 uses netlink. The loopback-only fixture can bring up the only
    # interface with a Linux ioctl, leaving the original namespace untouched.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        name = struct.pack("16sH22x", b"lo", 0)
        flags = struct.unpack_from("H", fcntl.ioctl(control, 0x8913, name), 16)[0]  # SIOCGIFFLAGS
        fcntl.ioctl(control, 0x8914, struct.pack("16sH22x", b"lo", flags | 1))  # SIOCSIFFLAGS, IFF_UP

    tenants = json.loads((HERE / "tenants.example.json").read_text())["tenants"]
    item = tenants[index]
    tenant = item["name"]
    egress, backend = f"127.0.0.{5 + index * 4}", f"127.0.0.{6 + index * 4}"
    listen_port, backend_port = str(item["listen_port"]), str(item["backend_port"])
    # The deployment renderer rejects loopback inputs. Substitute only the
    # three fixed test addresses after rendering the real configuration.
    config = render(tenants)[tenant].replace(item["listen_ip"], LISTENER)
    config = config.replace(item["egress_ip"], egress).replace(item["backend_ip"], backend)
    path = root / (tenant + ".cfg")
    path.write_text(config)

    with ExitStack() as cleanup:
        server = start(cleanup, [sys.executable, "-c", BACKEND, backend, backend_port, egress, tenant])
        proxy = start(cleanup, ["haproxy", "-db", "-f", str(path)])

        def ready():
            if server.poll() is not None or proxy.poll() is not None:
                raise RuntimeError("backend or frontend failed to start")
            try:
                with socket.create_connection((LISTENER, int(listen_port)), .3) as c, c.makefile("rb") as f:
                    c.sendall(b"ping\n")
                    return f.readline(256).startswith((tenant + " ").encode())
            except OSError:
                return False

        until(ready, "loopback frontend not ready")
        probe = start(cleanup, [sys.executable, "-c", REQUEST, CLIENT, str(SOURCE_PORT),
                                LISTENER, listen_port, str(root), tenant])
        if index == 0:
            until(lambda: (root / "stop-a").exists(), "missing shutdown request")
            stop(server)
            (root / "check").touch()
        if probe.wait(timeout=10):
            raise RuntimeError(f"{tenant} connection verification failed")


def main():
    if len(sys.argv) == 5 and sys.argv[1] == "--worker":
        worker(Path(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
        return 0
    if len(sys.argv) != 1:
        return 2
    if not shutil.which("haproxy") or not shutil.which("unshare"):
        print("BLOCKED: HAProxy and unshare are required.", file=sys.stderr)
        return 77
    namespace = os.readlink("/proc/self/ns/net")
    with tempfile.TemporaryDirectory(prefix="tenant-loopback-") as tmp, ExitStack() as cleanup:
        root = Path(tmp)
        workers = [start(cleanup, ["unshare", "--user", "--map-root-user", "--net", "--",
                                   sys.executable, __file__, "--worker", tmp, str(i), namespace])
                   for i in range(2)]

        def both_active():
            if any(p.poll() is not None for p in workers):
                raise RuntimeError("a namespace worker exited before both connections were active")
            return all((root / name).exists() for name in ("tenant-a", "tenant-b"))

        until(both_active, "both connections were not simultaneously active")
        for name in ("tenant-a", "tenant-b"):
            tuple_seen = json.loads((root / name).read_text())
            if tuple_seen != [[CLIENT, SOURCE_PORT], [LISTENER, 8080]]:
                raise RuntimeError(f"{name} did not use the expected TCP tuple")
        (root / "stop-a").touch()
        results = [p.wait(timeout=12) for p in workers]
        if any(results):
            raise RuntimeError("tenant disconnect or survivor check failed")
    print("PASS: two live sockets used identical IPv4/TCP tuples in separate namespaces; "
          "stopping one backend preserved the other connection.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
