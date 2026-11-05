#!/usr/bin/env python3
"""Nobody pings this machine: a netfilter chain on NF_LOCAL_IN, for the whole system.

    sudo python3 examples/netfilter/no_ping.py

Netfilter hooks see every packet the kernel routes, on every interface, so
there's nothing to attach to: priorities= places bpfilter among the other
netfilter users (nftables, iptables). It takes two different, non-zero
priorities, so bpfilter can replace the chain atomically.
Echo requests to this host are dropped, from the network namespace and from
the host itself (loopback goes through netfilter too); TCP is untouched.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # examples/_lab.py
from _lab import lab, listening, ping, show
from bpyfilter import ACCEPT, DROP, NF_LOCAL_IN, Chain
from bpyfilter.match import icmp, ip4


def report(when, net):
    print(f"{when:10} ns -> host: {show(net.ping_host()):8} host -> 127.0.0.1: {show(ping('127.0.0.1')):8} "
          f"tcp: {show(net.connects_to_host(8080))}")


with lab() as net, listening(net.host_ip, 8080):
    report("before", net)
    with Chain("example_nf_no_ping", NF_LOCAL_IN(priorities=(101, 102)), policy=ACCEPT).rule(
            ip4.proto == "icmp", icmp.type == "echo-request", verdict=DROP) as chain:
        report("installed", net)
        print("dropped (packets, bytes):", chain.counters().rules[0])
    report("after", net)
