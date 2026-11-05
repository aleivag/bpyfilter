#!/usr/bin/env python3
"""One-way ping: TC_EGRESS drops echo requests leaving an interface, not echo replies.

    sudo python3 examples/tc/egress_ping.py

Egress sees every packet this host sends on the interface, answers included:
dropping all ICMP would also stop the replies to the namespace's pings. Match
the ICMP type instead, and this host can't ping out while it still answers.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # examples/_lab.py
from _lab import lab, show
from bpyfilter import ACCEPT, DROP, TC_EGRESS, Chain
from bpyfilter.match import icmp, ip4


def report(when, net):
    print(f"{when:28} host -> ns: {show(net.ping_ns()):8} ns -> host: {show(net.ping_host())}")


with lab() as net:
    report("before", net)
    with Chain("example_tc_egress_ping", TC_EGRESS(ifindex=net.host_if), policy=ACCEPT).rule(
            ip4.proto == "icmp", icmp.type == "echo-request", verdict=DROP):
        report("drop outgoing echo-request", net)
    with Chain("example_tc_egress_ping", TC_EGRESS(ifindex=net.host_if), policy=ACCEPT).rule(
            ip4.proto == "icmp", verdict=DROP):
        report("drop all outgoing icmp", net)
