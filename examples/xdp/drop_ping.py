#!/usr/bin/env python3
"""Drop pings at the driver: XDP sees a packet before the kernel builds anything for it.

    sudo python3 examples/xdp/drop_ping.py

XDP only sees what arrives on one interface (ingress), so the chain is attached
with ifindex=: an index or a name (bpyfilter looks names up). Here it's the
host's end of a throwaway cable to a network namespace; the namespace can't
ping this host while the chain is in place, and TCP still gets through.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # examples/_lab.py
from _lab import lab, listening, show
from bpyfilter import ACCEPT, DROP, XDP, Chain
from bpyfilter.match import ip4

with lab() as net, listening(net.host_ip, 8080):
    print(f"{'before':16}ping: {show(net.ping_host()):8} tcp: {show(net.connects_to_host(8080))}")
    with Chain("example_xdp_drop_ping", XDP(ifindex=net.host_if), policy=ACCEPT).rule(
            ip4.proto == "icmp", verdict=DROP) as chain:
        print(f"{'XDP on ' + net.host_if:16}ping: {show(net.ping_host()):8} tcp: {show(net.connects_to_host(8080))}")
        print("dropped (packets, bytes):", chain.counters().rules[0])
    print(f"{'after':16}ping: {show(net.ping_host()):8} tcp: {show(net.connects_to_host(8080))}")
