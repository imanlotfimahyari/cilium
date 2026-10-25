#!/usr/bin/env python3
# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
# Copyright Authors of Cilium

"""Compile the focused socket implementation and verify sampled flag-off code.

This performs compiler/ELF checks, not packet execution. The VM runner separately
executes the verifier, actual endpoint pipeline and socket/lifecycle tests.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
BASELINE = "fe561573e0a8adc43bacbcc70bda0c9e01d6676d"

def program_sections(path):
    """Compare executable ELF64 sections, excluding BTF/debug/type names."""
    data = path.read_bytes()
    if data[:5] != b"\x7fELF\x02":
        raise ValueError("Expected an ELF64 BPF object")
    endian = "<" if data[5] == 1 else ">"
    offset = struct.unpack_from(endian + "Q", data, 40)[0]
    entry_size, count, names_index = struct.unpack_from(endian + "HHH", data, 58)
    entries = [struct.unpack_from(endian + "IIQQQQIIQQ", data, offset + i * entry_size)
               for i in range(count)]
    names_header = entries[names_index]
    names = data[names_header[4]:names_header[4] + names_header[5]]
    result = {}
    for header in entries:
        if not header[2] & 4:
            continue
        name = names[header[0]:].split(b"\0", 1)[0].decode()
        contents = data[header[4]:header[4] + header[5]]
        result[name] = hashlib.sha256(contents).hexdigest()
    return result



def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--clang", required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    baseline_ct = subprocess.check_output(["git", "show", BASELINE+":bpf/lib/conntrack.h"], cwd=ROOT)
    if baseline_ct != (ROOT/"bpf/lib/conntrack.h").read_bytes():
        raise AssertionError("the socket implementation must leave conntrack.h unchanged")
    print("PASS conntrack.h is byte-identical to baseline", flush=True)
    flags = [args.clang, "--target=bpf", "-O2", "-g", "-mcpu=v3", "-std=gnu99", "-nostdinc",
             "-I", str(ROOT/"bpf"), "-I", str(ROOT/"bpf/include"), "-I", str(ROOT/"bpf/tests"),
             "-Wall", "-Wextra", "-Werror", "-Wshadow", "-Wno-address-of-packed-member",
             "-Wno-unknown-warning-option", "-ftrap-function=__undefined_trap"]
    sources = {
        "bpf_vtep_return.o": "bpf/bpf_vtep_return.c",
        "socket_handoff.o": "contrib/vtep-return-affinity/live/testdata/socket_handoff.c",
        "socket_core.o": "contrib/vtep-return-affinity/live/testdata/socket_core.c",
        "socket_timewait_core.o": "contrib/vtep-return-affinity/live/testdata/socket_timewait_core.c",
        "socket_identity.o": "contrib/vtep-return-affinity/live/testdata/socket_identity.c",
        "timewait_owner.o": "contrib/vtep-return-affinity/live/testdata/timewait_owner.c",
        "timewait_packet.o": "contrib/vtep-return-affinity/live/testdata/timewait_packet.c",
        "vm-bpf/tc_vtep_return_core.o": "bpf/tests/tc_vtep_return_core.c",
        "vm-bpf/conntrack_test.o": "bpf/tests/conntrack_test.c",
    }
    for name, source in sources.items():
        target = output/name
        target.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(flags+["-c", source, "-o", str(target)], cwd=ROOT, check=True)
        print("PASS strict compilation: "+name, flush=True)
    with tempfile.TemporaryDirectory(prefix="vtep-disabled-") as tmp:
        directory = Path(tmp)
        source = directory/"bpf_lxc.c"
        source.write_bytes(subprocess.check_output(["git", "show", BASELINE+":bpf/bpf_lxc.c"], cwd=ROOT))
        overlay = directory/"baseline.json"
        overlay.write_text(json.dumps({"version": 0, "roots": [{"type": "file",
            "name": str(ROOT/"bpf/bpf_lxc.c"), "external-contents": str(source)}]}))
        for test in ["overlay", "tc_lxc_policy_drop"]:
            objects = []
            for name, extra in [("baseline", ["-ivfsoverlay", str(overlay)]), ("current", [])]:
                obj = directory/(test+"-"+name+".o")
                subprocess.run(flags+extra+["-c", "bpf/tests/"+test+".c", "-o", str(obj)], cwd=ROOT, check=True)
                objects.append(program_sections(obj))
            if not objects[0] or objects[0] != objects[1]:
                raise AssertionError("flag-off executable code changed: "+test)
            print("PASS identical flag-off executable sections: "+test, flush=True)


if __name__ == "__main__":
    main()
