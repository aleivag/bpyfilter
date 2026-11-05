#!/usr/bin/env python3
"""A source blocklist at the driver: a set of addresses whose packets XDP drops.

    sudo python3 examples/xdp/blocklist.py

The classic XDP use: shed traffic from known-bad sources before it costs the
kernel anything. The namespace has two addresses; one is blocked, then the
other joins it with a set update in place (no reattaching, nothing dropped
in between).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # examples/_lab.py
from _lab import lab, show
from bpyfilter import ACCEPT, DROP, XDP, Chain
from bpyfilter.match import ip4


def report(when, net):
    print(f"{when:18} " + "  ".join(f"from {a}: {show(net.ping_host(a)):7}" for a in net.ns_ips))


with lab() as net:
    chain = Chain("example_xdp_blocklist", XDP(ifindex=net.host_if), policy=ACCEPT)
    banned = chain.add_set("banned", ip4.saddr, [net.ns_ips[1]])
    chain.rule(banned, verdict=DROP)
    with chain:
        report("one banned", net)
        banned.add(net.ns_ips[0])
        banned.update_chain()
        report("both banned", net)
        print("banned:", sorted(banned), " dropped (packets, bytes):", chain.counters().rules[0])
