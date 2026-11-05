#!/usr/bin/env python3
"""Refuse connect() itself: a CGROUP_SOCK_ADDR_CONNECT4 chain fails it with EPERM, at once.

    sudo python3 examples/cgroup_sock_addr/connect4.py

A cgroup_skb chain drops packets: a blocked connect() sends SYNs that vanish,
and gives up only when it times out. A sock_addr chain runs when the program
calls connect(), before any packet exists, and a DROP there makes the call
fail right away with "Operation not permitted". The same rule, both ways, for
a command in a scratch cgroup connecting to a local port.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # examples/_lab.py
from _lab import listening, run_in, scratch_cgroup
from bpyfilter import ACCEPT, CGROUP_SKB_EGRESS, CGROUP_SOCK_ADDR_CONNECT4, DROP, Chain
from bpyfilter.match import tcp

PROBE = """
import socket, time
start = time.monotonic()
try:
    socket.create_connection(("127.0.0.1", 9090), timeout=2).close()
    outcome = "connected"
except OSError as e:
    outcome = type(e).__name__ + ": " + (e.strerror or str(e))
print(f"{outcome} after {time.monotonic() - start:.2f}s")
"""

with scratch_cgroup("bpyfilter-connect4") as cg, listening("127.0.0.1", 9090):
    print(f"{'no chain':26} {run_in(cg, ['python3', '-c', PROBE]).stdout.strip()}")
    for hook in (CGROUP_SKB_EGRESS, CGROUP_SOCK_ADDR_CONNECT4):
        with Chain("example_connect4", hook(cgpath=cg), policy=ACCEPT).rule(
                tcp.dport == 9090, verdict=DROP):
            print(f"{hook.name:26} {run_in(cg, ['python3', '-c', PROBE]).stdout.strip()}")
