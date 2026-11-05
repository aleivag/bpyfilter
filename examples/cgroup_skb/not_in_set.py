#!/usr/bin/env python3
"""'Not in a set': allow ping to any address except the blocked ones.

    sudo python3 examples/cgroup_skb/not_in_set.py

Any matcher can be negated, sets included: ~blocked is
"(ip4.daddr) not in blocked".
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # examples/_lab.py
from _lab import ping, scratch_cgroup, show
from bpyfilter import ACCEPT, CGROUP_SKB_EGRESS, DROP, Chain
from bpyfilter.match import ip4

with scratch_cgroup("bpyfilter-not-in-set") as cg:
    chain = Chain("example_not_in_set", CGROUP_SKB_EGRESS(cgpath=cg), policy=DROP)
    blocked = chain.add_set("blocked", ip4.daddr, ["127.0.0.2"])
    chain.rule(~blocked, ip4.proto == "icmp", verdict=ACCEPT)     # icmp, and not in blocked
    with chain:
        for address in ("127.0.0.1", "127.0.0.2", "127.0.0.3"):
            print(f"{address:10}  inside: {show(ping(address, cg))}")
