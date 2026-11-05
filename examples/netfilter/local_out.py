#!/usr/bin/env python3
"""A blocklist for the whole machine: NF_LOCAL_OUT drops what any process sends to it.

    sudo python3 examples/netfilter/local_out.py [ADDRESS ...]

cgroup_skb/blocklist.py does this for the processes of one cgroup; on
NF_LOCAL_OUT, every packet this host sends is checked against the set,
whichever process sent it. Defaults to two loopback addresses, so it runs
offline.
"""

import sys
from ipaddress import ip_address
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # examples/_lab.py
from _lab import ping, show
from bpyfilter import ACCEPT, DROP, NF_LOCAL_OUT, Chain
from bpyfilter.match import ip4

blocked_addresses = [ip_address(a) for a in sys.argv[1:]] or [ip_address("127.0.0.2"), ip_address("127.0.0.3")]

chain = Chain("example_nf_local_out", NF_LOCAL_OUT(priorities=(101, 102)), policy=ACCEPT)
blocked = chain.add_set("blocked", ip4.daddr, blocked_addresses)
chain.rule(blocked, verdict=DROP)

with chain:
    for address in [ip_address("127.0.0.1"), *blocked_addresses]:
        print(f"{str(address):15}  {show(ping(address))}")
    print("blocked (packets, bytes):", chain.counters().rules[0])
