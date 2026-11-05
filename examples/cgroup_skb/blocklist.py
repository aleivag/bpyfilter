#!/usr/bin/env python3
"""A blocklist for one command: a named set of addresses it can't reach.

    sudo python3 examples/cgroup_skb/blocklist.py [ADDRESS ...]

One rule, one set: bpfilter looks each packet's destination up in a hash map,
so a thousand addresses cost the same as two. Defaults to two loopback
addresses, so it runs offline.
"""

import sys
from ipaddress import ip_address
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # examples/_lab.py
from _lab import ping, scratch_cgroup, show
from bpyfilter import ACCEPT, CGROUP_SKB_EGRESS, DROP, Chain
from bpyfilter.match import ip4

blocked_addresses = [ip_address(a) for a in sys.argv[1:]] or [ip_address("127.0.0.2"), ip_address("127.0.0.3")]

with scratch_cgroup("bpyfilter-blocklist") as cg:
    chain = Chain("example_blocklist", CGROUP_SKB_EGRESS(cgpath=cg), policy=ACCEPT)
    blocked = chain.add_set("blocked", ip4.daddr, blocked_addresses)
    chain.rule(blocked, verdict=DROP)                 # "(ip4.daddr) in blocked"
    with chain:
        for address in [ip_address("127.0.0.1"), *blocked_addresses]:
            print(f"{str(address):15}  outside: {show(ping(address)):8} inside: {show(ping(address, cg))}")
        print("blocked (packets, bytes):", chain.counters().rules[0])
