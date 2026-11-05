#!/usr/bin/env python3
"""An allowlist for one command: policy DROP, and a set of networks it may reach.

    sudo python3 examples/cgroup_skb/allowlist.py

The chain's policy is "everything else": here, drop. Only destinations in the
`allowed` set (a longest-prefix-match trie, since its key is a network field)
get through. Runs offline: 127.0.0.1/32 is allowed, the rest of 127/8 is not.
"""

import sys
from ipaddress import ip_network
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # examples/_lab.py
from _lab import ping, scratch_cgroup, show
from bpyfilter import ACCEPT, CGROUP_SKB_EGRESS, DROP, Chain
from bpyfilter.match import ip4

with scratch_cgroup("bpyfilter-allowlist") as cg:
    chain = Chain("example_allowlist", CGROUP_SKB_EGRESS(cgpath=cg), policy=DROP)
    allowed = chain.add_set("allowed", ip4.dnet, [ip_network("127.0.0.1/32"), ip_network("10.0.0.0/8")])
    chain.rule(allowed, verdict=ACCEPT)
    with chain:
        for address in ("127.0.0.1", "127.0.0.2", "127.0.0.9"):
            print(f"{address:10}  inside: {show(ping(address, cg))}")
        counters = chain.counters()
        print("allowed (packets, bytes):", counters.rules[0], "| dropped by the policy:", counters.policy)
