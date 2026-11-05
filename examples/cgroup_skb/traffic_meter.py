#!/usr/bin/env python3
"""A traffic meter for one command: count its packets per protocol, block nothing.

    sudo python3 examples/cgroup_skb/traffic_meter.py [command ...]

Each rule has verdict CONTINUE: it counts the packets it matches, then lets
evaluation go on to the next rule, and finally to the policy (ACCEPT). So the
counters measure the command's traffic without changing it.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # examples/_lab.py
from _lab import run_in, scratch_cgroup
from bpyfilter import ACCEPT, CGROUP_SKB_EGRESS, CONTINUE, Chain
from bpyfilter.match import ip4, meta

cmd = sys.argv[1:] or ["sh", "-c", "ping -c3 -i0.2 127.0.0.1; python3 -c "
                       "'import socket; s = socket.socket(type=socket.SOCK_DGRAM); "
                       "[s.sendto(b\"x\", (\"127.0.0.1\", 9)) for _ in range(5)]'"]

protocols = {"icmp": ip4.proto == "icmp", "udp": meta.l4_proto == "udp", "tcp": meta.l4_proto == "tcp"}

with scratch_cgroup("bpyfilter-meter") as cg:
    chain = Chain("example_meter", CGROUP_SKB_EGRESS(cgpath=cg), policy=ACCEPT)
    for match in protocols.values():
        chain.rule(match, verdict=CONTINUE)
    with chain:
        returncode = run_in(cg, cmd).returncode
        counters = chain.counters()
        print(f"command exited with {returncode}; what it sent:")
        for name, (packets, size) in zip(protocols, counters.rules):
            print(f"  {name:5} {packets:4} packets  {size:6} bytes")
        print(f"  total {counters.policy[0]:4} packets  {counters.policy[1]:6} bytes (all reached the policy)")
