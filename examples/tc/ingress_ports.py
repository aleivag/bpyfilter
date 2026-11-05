#!/usr/bin/env python3
"""Close ports on an interface: TC_INGRESS drops TCP to some ports as packets come in.

    sudo python3 examples/tc/ingress_ports.py

TC sits after the driver, where the kernel already has a full packet (an
skb); like XDP it's attached to one interface with ifindex=. This host listens
on three ports; from the namespace, only the ones not in the set answer.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # examples/_lab.py
from _lab import lab, listening, show
from bpyfilter import ACCEPT, DROP, TC_INGRESS, Chain
from bpyfilter.match import tcp

PORTS = (8080, 9090, 2222)

with lab() as net, listening(net.host_ip, *PORTS):
    with Chain("example_tc_ingress_ports", TC_INGRESS(ifindex=net.host_if), policy=ACCEPT).rule(
            tcp.dport.isin([9090, 2222]), verdict=DROP):
        for port in PORTS:
            print(f"{net.host_ip}:{port}  from the namespace: {show(net.connects_to_host(port))}")
