# This file was not reviewed by a human before submission
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium
"""Exercise duplicate IPv4/TCP tuples across two independent ingress networks."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from render import render

HERE = Path(__file__).resolve().parent
CLIENT = "198.18.0.2"
SOURCE_PORT = 49000
BACKEND = """
import secrets, socket, sys, threading
ip, port, egress, tenant = sys.argv[1:]
def serve(conn):
    with conn, conn.makefile('rb') as stream:
        conn.settimeout(8)
        if conn.getpeername()[0] != egress:
            return
        reply = (tenant + ' ' + secrets.token_hex(8) + '\\n').encode()
        try:
            for line in stream:
                if line != b'ping\\n':
                    return
                conn.sendall(reply)
        except OSError:
            return
with socket.create_server((ip, int(port))) as listener:
    while True:
        conn, _ = listener.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()
"""

REQUEST = """
import json, socket, sys, time
from pathlib import Path
source, sport, listen, dport, root, tenant = sys.argv[1:]
root = Path(root)
with socket.create_connection((listen, int(dport)), timeout=3,
                              source_address=(source, int(sport))) as conn:
    conn.settimeout(8)
    with conn.makefile('rb') as stream:
        conn.sendall(b'ping\\n')
        reply = stream.readline(256)
        if not reply.startswith((tenant + ' ').encode()):
            raise RuntimeError('unexpected backend: ' + repr(reply))
        temporary = root / (tenant + '.tmp')
        temporary.write_text(json.dumps([conn.getsockname(), conn.getpeername()]))
        temporary.rename(root / tenant)
        deadline = time.monotonic() + 8
        while not (root / 'check').exists():
            if time.monotonic() > deadline:
                raise RuntimeError('coordination timeout')
            time.sleep(.02)
        try:
            conn.sendall(b'ping\\n')
            again = stream.readline(256)
        except ConnectionError:
            again = b''
        if tenant == 'tenant-a':
            if again:
                raise RuntimeError('retired backend unexpectedly answered')
        elif again != reply:
            raise RuntimeError('unrelated tenant lost its original connection')
"""


def cmd(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=8)


def run_lab(root, tenants, haproxy):
    # The outer unshare command gives this fixture its own initial netns.
    # All named namespaces and veths are local to that disposable environment.
    os.environ["IP_NETNS_DIR"] = str(root / "netns")
    (root / "netns").mkdir()
    with ExitStack() as cleanup:
        def namespace(name):
            cmd("ip", "netns", "add", name)
            cleanup.callback(cmd, "ip", "netns", "del", name, check=False)
            cmd("ip", "-n", name, "link", "set", "lo", "up")
            return name

        def veth(name, left, left_ip, right, right_ip):
            cmd("ip", "link", "add", name + "a", "type", "veth", "peer", "name", name + "b")
            for suffix, ns, ip in (("a", left, left_ip), ("b", right, right_ip)):
                device = name + suffix
                cmd("ip", "link", "set", device, "netns", ns)
                cmd("ip", "-n", ns, "addr", "add", ip, "dev", device)
                cmd("ip", "-n", ns, "link", "set", device, "up")

        def launch(ns, *args):
            proc = subprocess.Popen(["ip", "netns", "exec", ns, *args])
            cleanup.callback(stop, proc)
            return proc

        backend = namespace("backends")
        configs = render(tenants)
        clients, servers = [], []
        for i, item in enumerate(tenants):
            edge, client = namespace(f"edge{i}"), namespace(f"client{i}")
            veth(f"lan{i}", client, CLIENT + "/24", edge, item["listen_ip"] + "/24")
            veth(f"wan{i}", edge, item["egress_ip"] + "/30", backend, item["backend_ip"] + "/30")
            servers.append(launch(backend, sys.executable, "-c", BACKEND, item["backend_ip"],
                                  str(item["backend_port"]), item["egress_ip"], item["name"]))
            path = root / (item["name"] + ".cfg")
            path.write_text(configs[item["name"]])
            launch(edge, haproxy, "-db", "-f", str(path))
            clients.append((client, item))

        # Probe the actual path before fixing the source port for both clients.
        for client, item in clients:
            until(lambda: cmd("ip", "netns", "exec", client, sys.executable, "-c",
                              "import socket,sys; s=socket.create_connection((sys.argv[1],int(sys.argv[2])),.3); "
                              "s.sendall(b'ping\\n'); sys.exit(not s.makefile('rb').readline(256).startswith(sys.argv[3].encode()+b' '))",
                              item["listen_ip"], str(item["listen_port"]), item["name"],
                              check=False).returncode == 0, "frontend not ready")

        running = [launch(client, sys.executable, "-c", REQUEST, CLIENT, str(SOURCE_PORT),
                          item["listen_ip"], str(item["listen_port"]), str(root), item["name"])
                   for client, item in clients]
        records = [root / item["name"] for item in tenants]
        def both_active():
            if any(proc.poll() is not None for proc in running):
                raise RuntimeError("a connection exited before both were active")
            return all(path.exists() for path in records)
        until(both_active, "both connections were not simultaneously active")
        expected = [[CLIENT, SOURCE_PORT], [tenants[0]["listen_ip"], tenants[0]["listen_port"]]]
        if any(json.loads(path.read_text()) != expected for path in records):
            raise RuntimeError("the observed IPv4/TCP tuples differ")
        stop(servers[0])
        (root / "check").touch()
        results = [proc.wait(timeout=10) for proc in running]
        if any(results):
            raise RuntimeError("tenant disconnect or survivor check failed")


def until(condition, message):
    deadline = time.monotonic() + 6
    while not condition():
        if time.monotonic() >= deadline:
            raise RuntimeError(message)
        time.sleep(.05)


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)


def main():
    if sys.argv[1:] != ["--isolated-lab"]:
        print("Run through the unshare command in README.md.", file=sys.stderr)
        return 2
    haproxy = shutil.which("haproxy")
    if not haproxy or not shutil.which("ip"):
        print("BLOCKED: HAProxy and iproute2 are required.", file=sys.stderr)
        return 77
    if cmd("ip", "link", "show", check=False).returncode:
        print("BLOCKED: netlink access is unavailable.", file=sys.stderr)
        return 77
    try:
        isolated = os.readlink("/proc/self/ns/net") != os.readlink("/proc/1/ns/net")
    except OSError:
        isolated = False
    if not isolated:
        print("BLOCKED: cannot verify that the network namespace is disposable.", file=sys.stderr)
        return 77
    tenants = json.loads((HERE / "tenants.example.json").read_text())["tenants"]
    try:
        with tempfile.TemporaryDirectory(prefix="tenant-edge-") as tmp:
            run_lab(Path(tmp), tenants, haproxy)
    except subprocess.CalledProcessError as exc:
        error = exc.stderr.strip() if exc.stderr else str(exc)
        print("FAILED: " + error, file=sys.stderr)
        return 1
    print("PASS: simultaneous identical IPv4/TCP tuples used separate backends; "
          "disconnecting one preserved the other connection.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
