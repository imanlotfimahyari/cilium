#!/usr/bin/env python3
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
# Copyright Authors of Cilium

"""Run isolated privileged BPF tests in a network-disconnected QEMU/TCG guest.

Supply a trusted Linux kernel, static BusyBox, QEMU and the statically compiled
Cilium bpftest binary. Only the explicitly supplied test artifacts enter the
initramfs; no host filesystem or network is exposed to the guest.
"""

import argparse
import ctypes
import ctypes.util
import gzip
import hashlib
import json
import os
import re
from pathlib import Path
import select
import shlex
import stat
import subprocess
import tempfile
import time

from validation_results import validate_output


def file_sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def bpf_tree_sha256(root):
    digest = hashlib.sha256()
    for source in sorted(root.rglob("*")):
        relative = source.relative_to(root)
        if source.is_file() and source.suffix in {".c", ".h"} and "tests" not in relative.parts:
            digest.update(str(relative).encode() + b"\0")
            digest.update(bytes.fromhex(file_sha256(source)))
    return digest.hexdigest()


def entry(name, mode, data=b"", major=0, minor=0):
    name = name.encode() + b"\0"
    fields = [1, mode, 0, 0, 1, 0, len(data), 0, 0, major, minor, len(name), 0]
    header = b"070701" + b"".join(f"{v:08x}".encode() for v in fields)
    prefix = header + name
    return prefix + b"\0" * (-len(prefix) % 4) + data + b"\0" * (-len(data) % 4)


def decompress_module(path):
    data = path.read_bytes()
    if path.suffix != ".zst":
        return data
    lib = ctypes.CDLL(ctypes.util.find_library("zstd"))
    lib.ZSTD_getFrameContentSize.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    lib.ZSTD_getFrameContentSize.restype = ctypes.c_uint64
    lib.ZSTD_decompress.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
    lib.ZSTD_decompress.restype = ctypes.c_size_t
    lib.ZSTD_isError.argtypes = [ctypes.c_size_t]
    lib.ZSTD_isError.restype = ctypes.c_uint
    size = lib.ZSTD_getFrameContentSize(data, len(data))
    if size > 16 * 1024 * 1024:
        raise ValueError("Unexpected module size")
    output = ctypes.create_string_buffer(size)
    result = lib.ZSTD_decompress(output, size, data, len(data))
    if lib.ZSTD_isError(result):
        raise ValueError("Module decompression failed")
    return output.raw[:result]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--qemu-root", type=Path, required=True)
    p.add_argument("--kernel", type=Path, required=True)
    p.add_argument("--busybox", type=Path, required=True)
    p.add_argument("--runner", type=Path, required=True)
    p.add_argument("--agent-tests", type=Path)
    p.add_argument("--agent-test-run", default=".")
    p.add_argument("--recovery-disk", type=Path,
                   help="Explicit disposable raw ext4 image, shared only between isolated boots")
    p.add_argument("--recovery-stage", choices=["prepare", "verify"])
    p.add_argument("--live-tests", type=Path)
    p.add_argument("--socket-object", type=Path)
    p.add_argument("--handoff-object", type=Path)
    p.add_argument("--core-object", type=Path)
    p.add_argument("--timewait-core-object", type=Path)
    p.add_argument("--timewait-object", type=Path)
    p.add_argument("--timewait-packet-object", type=Path)
    p.add_argument("--live-test-run", default=".", help="Go test name expression for focused live validation")
    p.add_argument("--runtime-object", type=Path)
    p.add_argument("--full-agent", type=Path)
    p.add_argument("--previous-full-agent", type=Path,
                   help="Distinct previous prototype binary for actual cross-version tests")
    p.add_argument("--previous-source-bpf", type=Path,
                   help="Previous binary's own BPF source tree; never substitute the current tree")
    p.add_argument("--previous-agent-mode", choices=["compatible", "missing-hashdance"], default="compatible",
                   help="v15/v16 compatible transitions, or v15 refusal on the reviewed Linux 6.12 target change")
    p.add_argument("--clang", type=Path)
    p.add_argument("--source-bpf", type=Path)
    p.add_argument("--netfilter-root", type=Path)
    p.add_argument("--memory", default="768M")
    p.add_argument("--accelerator", choices=["tcg", "kvm"], default="tcg",
                   help="KVM requires /dev/kvm; never falls back silently to emulation")
    p.add_argument("--require-test", action="append", default=[],
                   help="Exact Go test name that must pass, including every executed subtest")
    p.add_argument("--report", type=Path, help="Machine-readable coverage and execution metadata")
    p.add_argument("--bpf-dir", type=Path, required=True)
    p.add_argument("--module-root", type=Path)
    p.add_argument("--log", type=Path, required=True)
    p.add_argument("--timeout", type=int, default=240)
    args = p.parse_args()
    if args.accelerator == "kvm" and not os.access("/dev/kvm", os.R_OK | os.W_OK):
        p.error("KVM requested but /dev/kvm is unavailable; native performance validation is blocked")
    if bool(args.recovery_disk) != bool(args.recovery_stage):
        p.error("--recovery-disk and --recovery-stage must be supplied together")
    if args.recovery_disk and not (args.agent_tests and args.runtime_object and args.recovery_disk.is_file()):
        p.error("recovery requires agent tests, runtime object and an existing disposable regular disk image")
    if args.socket_object and not args.live_tests:
        p.error("--socket-object requires --live-tests")
    if args.handoff_object and not args.live_tests:
        p.error("--handoff-object requires --live-tests")
    if args.core_object and not args.live_tests:
        p.error("--core-object requires --live-tests")
    if args.timewait_core_object and not args.live_tests:
        p.error("--timewait-core-object requires --live-tests")
    if args.timewait_object and not args.live_tests:
        p.error("--timewait-object requires --live-tests")
    if args.timewait_packet_object and not args.live_tests:
        p.error("--timewait-packet-object requires --live-tests")
    if args.full_agent and not (args.clang and args.source_bpf and args.live_tests):
        p.error("--full-agent requires --clang, --source-bpf and --live-tests")
    if bool(args.previous_full_agent) != bool(args.previous_source_bpf):
        p.error("--previous-full-agent and --previous-source-bpf must be supplied together")
    if args.previous_full_agent and not args.full_agent:
        p.error("--previous-full-agent requires --full-agent")
    if args.previous_agent_mode != "compatible" and not args.previous_full_agent:
        p.error("--previous-agent-mode requires a previous agent binary and source tree")
    if args.full_agent and not (args.source_bpf.is_dir() and args.netfilter_root and args.netfilter_root.is_dir()):
        p.error("--full-agent requires a BPF source directory and --netfilter-root for its required iptables runtime")
    if args.previous_full_agent and not args.previous_source_bpf.is_dir():
        p.error("--previous-source-bpf must be a directory")
    provenance = {}
    if args.full_agent:
        provenance = {"agent_sha256": file_sha256(args.full_agent),
                      "bpf_tree_sha256": bpf_tree_sha256(args.source_bpf),
                      "clang_sha256": file_sha256(args.clang)}
    if args.previous_full_agent:
        provenance.update(previous_agent_sha256=file_sha256(args.previous_full_agent),
                          previous_bpf_tree_sha256=bpf_tree_sha256(args.previous_source_bpf),
                          previous_agent_mode=args.previous_agent_mode)
        if provenance["agent_sha256"] == provenance["previous_agent_sha256"]:
            p.error("cross-version tests require two distinct agent binaries")

    # Resolve actual .modinfo dependencies before packaging. The agent opens
    # routing, XFRM and netfilter netlink families even when encryption is off.
    requested = ["udp_tunnel", "ip6_udp_tunnel", "veth", "cls_bpf", "sch_ingress", "sch_netem", "act_bpf", "vxlan"]
    if args.full_agent:
        requested += ["inet_diag", "tcp_diag", "udp_diag", "netlink_diag", "unix_diag", "nfnetlink", "xfrm_user", "nf_conntrack_netlink"]
        requested += ["ip_tables", "iptable_filter", "iptable_mangle", "iptable_raw", "iptable_nat", "iptable_security", "ip6_tables", "ip6table_filter", "ip6table_mangle", "ip6table_raw", "ip6table_nat", "ip6table_security",
                      "xt_conntrack", "xt_tcpudp", "xt_mark", "xt_connmark", "xt_comment", "xt_socket", "xt_addrtype", "xt_CT", "xt_MASQUERADE", "xt_REDIRECT", "xt_TPROXY", "xt_physdev", "xt_set", "ip_set", "ip_set_hash_ip"]
    modules = {}
    visiting = set()
    def add_module(name):
        if not args.module_root or name in modules or name in visiting:
            return
        candidates = list(args.module_root.rglob(name + ".ko*"))
        if not candidates:
            return  # Built-in support is also allowed.
        visiting.add(name)
        data = decompress_module(candidates[0])
        match = re.search(rb"(?:^|\x00)depends=([A-Za-z0-9_,\-]*)\x00", data)
        if match:
            for dep in match[1].decode().split(","):
                if dep:
                    add_module(dep.replace("-", "_"))
        modules[name] = data
    for name in requested:
        add_module(name)

    init = """#!/bin/sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /sys/fs/bpf /sys/fs/cgroup /run/netns
mkdir -p /run/cilium/cgroupv2
mount -t bpf bpf /sys/fs/bpf
mount -t cgroup2 cgroup2 /sys/fs/cgroup
mount -t cgroup2 cgroup2 /run/cilium/cgroupv2
hostname vtep-lab
ip link set lo up
__RECOVERY_MOUNT__
for name in __VM_MODULES__; do
  [ ! -f "/modules/$name.ko" ] || insmod "/modules/$name.ko"
done
echo VTEP_VM_TEST_BEGIN
if [ -f /bpf_vtep_return.o ]; then export VTEP_RETURN_RUNTIME_OBJECT=/bpf_vtep_return.o; fi
if [ -x /cilium-agent ]; then export VTEP_RETURN_AGENT_BINARY=/cilium-agent; fi
if [ -x /previous-agent/cilium-agent ]; then
  export VTEP_RETURN_PREVIOUS_AGENT_BINARY=/previous-agent/cilium-agent
  export VTEP_RETURN_PREVIOUS_AGENT_MODE=__PREVIOUS_AGENT_MODE__
fi
echo VTEP_SUITE_BEGIN=conntrack
/bpftest -test.v -test.run '^TestBPF$' -bpf-test-path /bpf -test conntrack_test
two=$?
echo VTEP_SUITE_EXIT=conntrack:$two
core=0
if [ -f /bpf/tc_vtep_return_core.o ]; then
  echo VTEP_SUITE_BEGIN=core
  /bpftest -test.v -test.run '^TestBPF$' -bpf-test-path /bpf -test tc_vtep_return_core
  core=$?
  echo VTEP_SUITE_EXIT=core:$core
fi
three=0
if [ -x /agenttests ]; then
  echo VTEP_SUITE_BEGIN=agent
  PRIVILEGED_TESTS=1 VTEP_RETURN_ISOLATED_VM=1 /agenttests -test.v -test.run __AGENT_TEST_RUN__
  three=$?
  echo VTEP_SUITE_EXIT=agent:$three
fi
four=0
if [ -x /livetest ]; then
  echo VTEP_SUITE_BEGIN=live
  if [ -f /socket_identity.o ]; then
    export VTEP_RETURN_SOCKET_OBJECT=/socket_identity.o
  fi
  if [ -f /socket_handoff.o ]; then
    export VTEP_RETURN_HANDOFF_OBJECT=/socket_handoff.o
  fi
  if [ -f /socket_core.o ]; then
    export VTEP_RETURN_CORE_OBJECT=/socket_core.o
  fi
  if [ -f /socket_timewait_core.o ]; then
    export VTEP_RETURN_TIMEWAIT_CORE_OBJECT=/socket_timewait_core.o
  fi
  if [ -f /timewait_owner.o ]; then
    export VTEP_RETURN_TIMEWAIT_OBJECT=/timewait_owner.o
  fi
  if [ -f /timewait_packet.o ]; then
    export VTEP_RETURN_TIMEWAIT_PACKET_OBJECT=/timewait_packet.o
  fi
  PRIVILEGED_TESTS=1 VTEP_RETURN_ISOLATED_VM=1 /livetest -test.v -test.run __LIVE_TEST_RUN__
  four=$?
  echo VTEP_SUITE_EXIT=live:$four
fi
result=0
[ "$two" = 0 ] && [ "$core" = 0 ] && [ "$three" = 0 ] && [ "$four" = 0 ] || result=1
__RECOVERY_UNMOUNT__
echo VTEP_VM_EXIT=$result
poweroff -f
"""
    init = init.replace("__VM_MODULES__", " ".join(modules)).replace("__LIVE_TEST_RUN__", shlex.quote(args.live_test_run))
    init = init.replace("__AGENT_TEST_RUN__", shlex.quote(args.agent_test_run))
    init = init.replace("__PREVIOUS_AGENT_MODE__", shlex.quote(args.previous_agent_mode))
    init = init.replace("__RECOVERY_MOUNT__", (
        "mkdir -p /recovery\nmount -t ext4 /dev/vda /recovery || { echo VTEP_VM_EXIT=1; poweroff -f; }\n"
        "export VTEP_RETURN_RECOVERY_STAGE=" + shlex.quote(args.recovery_stage)
    ) if args.recovery_disk else "")
    init = init.replace("__RECOVERY_UNMOUNT__", "sync\numount /recovery || result=1" if args.recovery_disk else "")
    with tempfile.TemporaryDirectory(prefix="cilium-vtep-vm-") as tmp:
        archive = Path(tmp) / "tests.cpio.gz"
        with gzip.open(archive, "wb", compresslevel=1) as out:
            for directory in ["bin", "dev", "proc", "sys", "run", "tmp", "bpf", "modules"]:
                out.write(entry(directory, stat.S_IFDIR | 0o755))
            out.write(entry("dev/console", stat.S_IFCHR | 0o600, major=5, minor=1))
            out.write(entry("dev/null", stat.S_IFCHR | 0o666, major=1, minor=3))
            out.write(entry("bin/busybox", stat.S_IFREG | 0o755, args.busybox.read_bytes()))
            out.write(entry("bin/sh", stat.S_IFLNK | 0o777, b"busybox"))
            out.write(entry("etc", stat.S_IFDIR | 0o755))
            out.write(entry("root", stat.S_IFDIR | 0o700))
            out.write(entry("etc/passwd", stat.S_IFREG | 0o644, b"root:*:0:0::/root:/bin/sh\n"))
            out.write(entry("etc/group", stat.S_IFREG | 0o644, b"root:*:0:\n"))
            out.write(entry("init", stat.S_IFREG | 0o755, init.encode()))
            out.write(entry("bpftest", stat.S_IFREG | 0o755, args.runner.read_bytes()))
            if args.agent_tests:
                out.write(entry("agenttests", stat.S_IFREG | 0o755, args.agent_tests.read_bytes()))
            if args.live_tests:
                out.write(entry("livetest", stat.S_IFREG | 0o755, args.live_tests.read_bytes()))
            if args.core_object:
                out.write(entry("socket_core.o", stat.S_IFREG | 0o644, args.core_object.read_bytes()))
            if args.timewait_core_object:
                out.write(entry("socket_timewait_core.o", stat.S_IFREG | 0o644, args.timewait_core_object.read_bytes()))
            if args.timewait_object:
                out.write(entry("timewait_owner.o", stat.S_IFREG | 0o644, args.timewait_object.read_bytes()))
            if args.timewait_packet_object:
                out.write(entry("timewait_packet.o", stat.S_IFREG | 0o644, args.timewait_packet_object.read_bytes()))
            if args.runtime_object:
                out.write(entry("bpf_vtep_return.o", stat.S_IFREG | 0o644, args.runtime_object.read_bytes()))
            if args.full_agent:
                out.write(entry("cilium-agent", stat.S_IFREG | 0o755, args.full_agent.read_bytes()))
                out.write(entry("bin/clang", stat.S_IFREG | 0o755, args.clang.read_bytes()))
                for directory in ["var", "var/lib"]:
                    out.write(entry(directory, stat.S_IFDIR | 0o755))
                # Stage each version separately. The fixture installs its own
                # source at the same canonical path before starting a binary,
                # matching an image transition without path-dependent tags.
                trees = [(args.source_bpf, "var/lib/cilium-source")]
                if args.previous_full_agent:
                    # components.IsCiliumAgent identifies the process by argv[0].
                    # Distinguish versions by directory, retaining the real name.
                    out.write(entry("previous-agent", stat.S_IFDIR | 0o755))
                    out.write(entry("previous-agent/cilium-agent", stat.S_IFREG | 0o755, args.previous_full_agent.read_bytes()))
                    trees.append((args.previous_source_bpf, "var/lib/cilium-previous"))
                for source_root, library_root in trees:
                    out.write(entry(library_root, stat.S_IFDIR | 0o755))
                    out.write(entry(library_root + "/bpf", stat.S_IFDIR | 0o755))
                    for source in sorted(source_root.rglob("*")):
                        relative = source.relative_to(source_root)
                        if "tests" in relative.parts:
                            continue
                        rel = library_root + "/bpf/" + str(relative)
                        if source.is_dir():
                            out.write(entry(rel, stat.S_IFDIR | 0o755))
                        elif source.suffix in {".h", ".c"}:
                            out.write(entry(rel, stat.S_IFREG | 0o644, source.read_bytes()))
            if args.netfilter_root:
                out.write(entry("lib", stat.S_IFLNK | 0o777, b"usr/lib"))
                out.write(entry("lib64", stat.S_IFLNK | 0o777, b"usr/lib64"))
                for source in sorted(args.netfilter_root.rglob("*")):
                    rel = str(source.relative_to(args.netfilter_root))
                    if source.is_symlink():
                        out.write(entry(rel, stat.S_IFLNK | 0o777, os.readlink(source).encode()))
                    elif source.is_dir():
                        out.write(entry(rel, stat.S_IFDIR | 0o755))
                    elif source.is_file():
                        out.write(entry(rel, stat.S_IFREG | (source.stat().st_mode & 0o777), source.read_bytes()))
                for name in ["iptables", "iptables-save", "iptables-restore", "ip6tables", "ip6tables-save", "ip6tables-restore"]:
                    out.write(entry("bin/" + name, stat.S_IFLNK | 0o777, b"/usr/sbin/xtables-legacy-multi"))
            if args.socket_object:
                out.write(entry("socket_identity.o", stat.S_IFREG | 0o644, args.socket_object.read_bytes()))
            if args.handoff_object:
                out.write(entry("socket_handoff.o", stat.S_IFREG | 0o644, args.handoff_object.read_bytes()))
            for obj in sorted(args.bpf_dir.glob("*.o")):
                out.write(entry("bpf/" + obj.name, stat.S_IFREG | 0o644, obj.read_bytes()))
            if args.module_root:
                for name, data in modules.items():
                    out.write(entry("modules/" + name + ".ko", stat.S_IFREG | 0o644, data))
            out.write(entry("TRAILER!!!", 0))

        qemu = args.qemu_root / "usr/bin/qemu-system-x86_64"
        env = os.environ.copy()
        env["LD_LIBRARY_PATH"] = str(args.qemu_root / "usr/lib/x86_64-linux-gnu")
        env["QEMU_MODULE_DIR"] = str(args.qemu_root / "usr/lib/x86_64-linux-gnu/qemu")
        command = [
            str(qemu), "-nodefaults", "-no-user-config", "-no-reboot",
            "-machine", "pc,accel=" + args.accelerator,
            "-cpu", "host" if args.accelerator == "kvm" else "max",
            "-m", args.memory, "-smp", "2" if args.full_agent else "1",
            "-display", "none", "-monitor", "none", "-serial", "stdio", "-net", "none",
            "-L", str(args.qemu_root / "usr/share/qemu"),
            "-bios", str(args.qemu_root / "usr/share/seabios/bios-256k.bin"),
            "-kernel", str(args.kernel), "-initrd", str(archive),
            "-append", "console=ttyS0 rdinit=/init panic=-1 loglevel=3",
        ]
        if args.recovery_disk:
            command += ["-blockdev", json.dumps({"driver": "raw", "node-name": "recovery",
                        "file": {"driver": "file", "filename": str(args.recovery_disk.resolve())}}),
                        "-device", "virtio-blk-pci,drive=recovery"]
        args.log.parent.mkdir(parents=True, exist_ok=True)
        start = time.monotonic()
        result = None
        with args.log.open("w") as log:
            process = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            try:
                print("Started isolated privileged Linux test VM", flush=True)
                pending = ""
                while process.poll() is None:
                    if time.monotonic() - start > args.timeout:
                        raise TimeoutError("Privileged test VM timed out")
                    readable, _, _ = select.select([process.stdout], [], [], 1)
                    if not readable:
                        continue
                    chunk = os.read(process.stdout.fileno(), 65536).decode(errors="replace")
                    log.write(chunk)
                    log.flush()
                    pending += chunk
                    while "\n" in pending:
                        line, pending = pending.split("\n", 1)
                        if any(x in line for x in ["VTEP_VM_", "=== RUN", "--- PASS", "--- FAIL", "FAIL", "Error:"]):
                            print(line.rstrip(), flush=True)
                        if line.startswith("VTEP_VM_EXIT="):
                            result = int(line.strip().split("=", 1)[1])
                remainder = process.stdout.read().decode(errors="replace")
                log.write(remainder)
                for line in (pending + remainder).splitlines():
                    if line.startswith("VTEP_VM_EXIT="):
                        result = int(line.split("=", 1)[1])
                suites = ["conntrack"]
                if (args.bpf_dir / "tc_vtep_return_core.o").exists():
                    suites.append("core")
                if args.agent_tests:
                    suites.append("agent")
                if args.live_tests:
                    suites.append("live")
                log.flush()
                report = validate_output(args.log.read_text(), suites, args.require_test)
                report.update(accelerator=args.accelerator,
                              emulated=args.accelerator == "tcg",
                              native_performance_validated=False,
                              provenance=provenance,
                              kernel_sha256=hashlib.sha256(args.kernel.read_bytes()).hexdigest(),
                              elapsed_seconds=round(time.monotonic() - start, 3))
                if args.report:
                    args.report.parent.mkdir(parents=True, exist_ok=True)
                    args.report.write_text(json.dumps(report, indent=2) + "\n")
                if result != 0 or report["status"] != "PASS":
                    raise RuntimeError("Privileged VM evidence failed: " + "; ".join(report["errors"]))
                skipped = sum(len(r["skipped"]) for r in report["suites"].values())
                print(f"PASS executed privileged suites; {skipped} optional tests skipped", flush=True)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)


if __name__ == "__main__":
    main()
