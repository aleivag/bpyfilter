#!/usr/bin/env python3
"""Refuse sendto(): a CGROUP_SOCK_ADDR_SENDMSG4 chain stops UDP datagrams to some ports.

    sudo python3 examples/cgroup_sock_addr/sendmsg4.py

SENDMSG4 runs on every sendto()/sendmsg() of an unconnected UDP socket, with
the destination it's about to use: a DROP fails the call with EPERM, so the
program knows. (A connected UDP socket picked its destination at connect():
that's CONNECT4.) The command in the scratch cgroup sends one datagram to each
port; only the ones the chain allows arrive.
"""

import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # examples/_lab.py
from _lab import run_in, scratch_cgroup
from bpyfilter import ACCEPT, CGROUP_SOCK_ADDR_SENDMSG4, DROP, Chain
from bpyfilter.match import meta

PORTS = (7000, 7001, 7002)
PROBE = f"""
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for port in {PORTS}:
    try:
        s.sendto(b"hello", ("127.0.0.1", port))
        print(port, "sent")
    except OSError as e:
        print(port, type(e).__name__ + ":", e.strerror)
"""

receivers = {port: socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for port in PORTS}
for port, r in receivers.items():
    r.bind(("127.0.0.1", port))
    r.setblocking(False)

with scratch_cgroup("bpyfilter-sendmsg4") as cg:
    with Chain("example_sendmsg4", CGROUP_SOCK_ADDR_SENDMSG4(cgpath=cg), policy=ACCEPT).rule(
            meta.dport.isin([7001, 7002]), verdict=DROP):
        sent = dict(line.split(" ", 1) for line in run_in(cg, ["python3", "-c", PROBE]).stdout.splitlines())

for port, r in receivers.items():
    try:
        arrived = r.recv(100) == b"hello"
    except BlockingIOError:
        arrived = False
    print(f"udp/{port}  sendto: {sent[str(port)]:42} arrived: {'yes' if arrived else 'no'}")
    r.close()
