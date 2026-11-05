#!/usr/bin/env python3
"""One process can't connect, its sibling in the same cgroup can: meta.pid (bpfilter 0.8).

    sudo python3 examples/cgroup_sock_addr/per_pid.py

meta.pid is the process ID as seen from the initial PID namespace. It only
exists on the CGROUP_SOCK_ADDR_* hooks: they run in the process calling
connect() or sendmsg(), so there is a process to ask (the packet hooks see
packets, not processes). Two workers start in a scratch cgroup and wait;
the chain refuses connect() for the first one's PID only, then both try.

A PID only names a process until it exits: the kernel can then give the same
number to an unrelated process, which the rule would match. Keep such rules
short-lived, or remove the PID when the process exits (a pidfd tells you when).
Here the workers are our children: a child's PID can't be reused until we
wait() for it, so the rule can't hit anyone else while it's in place.
"""

import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # examples/_lab.py
from _lab import listening, scratch_cgroup
from bpyfilter import ACCEPT, CGROUP_SOCK_ADDR_CONNECT4, DROP, Chain
from bpyfilter.match import meta

WORKER = """
import socket, sys
sys.stdin.readline()                      # wait for the chain
try:
    socket.create_connection(("127.0.0.1", 9090), timeout=2).close()
    print("connected")
except OSError as e:
    print(type(e).__name__ + ":", e.strerror or e)
"""


def start_worker(cg):
    join = lambda: (cg / "cgroup.procs").write_text(str(os.getpid()))
    return subprocess.Popen(["python3", "-c", WORKER], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            text=True, preexec_fn=join)


with scratch_cgroup("bpyfilter-per-pid") as cg, listening("127.0.0.1", 9090):
    blocked, allowed = start_worker(cg), start_worker(cg)
    with Chain("example_per_pid", CGROUP_SOCK_ADDR_CONNECT4(cgpath=cg), policy=ACCEPT).rule(
            meta.pid == blocked.pid, verdict=DROP):
        for worker in (blocked, allowed):
            out, _ = worker.communicate("go\n", timeout=10)
            print(f"pid {worker.pid:<8} {'(in the rule)' if worker is blocked else '':14} {out.strip()}")
