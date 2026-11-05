#!/usr/bin/env python3
"""Ports: a range of TCP ports, and an (address, port) set, blocked for one command.

    sudo python3 examples/cgroup_skb/tcp_ports.py

Starts three local TCP listeners, then connects to each from inside the cgroup:
- tcp.dport.range(9000, 9999) drops a whole range of ports;
- key(ip4.daddr, tcp.dport).isin(...) is an inline set with a composite key:
  only that address *and* port together match.
"""

import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # examples/_lab.py
from _lab import scratch_cgroup, show, tcp_connects
from bpyfilter import ACCEPT, CGROUP_SKB_EGRESS, DROP, Chain
from bpyfilter.match import ip4, key, tcp

listeners = {}
for port in (8080, 9090, 2222):
    listeners[port] = socket.create_server(("127.0.0.1", port))

with scratch_cgroup("bpyfilter-ports") as cg:
    chain = (Chain("example_ports", CGROUP_SKB_EGRESS(cgpath=cg), policy=ACCEPT)
             .rule(tcp.dport.range(9000, 9999), verdict=DROP)
             .rule(key(ip4.daddr, tcp.dport).isin([("127.0.0.1", 2222)]), verdict=DROP))
    try:
        with chain:
            for port in listeners:
                print(f"127.0.0.1:{port}  outside: {show(tcp_connects('127.0.0.1', port)):8} "
                      f"inside: {show(tcp_connects('127.0.0.1', port, cg))}")
    finally:
        for listener in listeners.values():
            listener.close()
