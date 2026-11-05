#!/usr/bin/env python3
"""A firewall for one command: block ICMP and DNS for whatever runs in a cgroup.

    sudo python3 examples/per_cgroup_firewall.py [command ...]

Everything outside the cgroup is unaffected. Needs root and bpfilter.service.
(Name lookups through systemd-resolved still work: resolved sends the DNS
query from its own cgroup. Direct queries to port 53 from inside are dropped.)
"""

import os
import subprocess
import sys
from pathlib import Path

from bpyfilter import ACCEPT, CGROUP_SKB_EGRESS, DROP, Chain
from bpyfilter.match import ip4, meta, udp

cmd = sys.argv[1:] or ["ping", "-c1", "-W1", "1.1.1.1"]
cg = Path("/sys/fs/cgroup/bpyfilter-example")
cg.mkdir(exist_ok=True)

chain = (Chain("example_fw", CGROUP_SKB_EGRESS(cgpath=cg), policy=ACCEPT)
         .rule(ip4.proto == "icmp", verdict=DROP)                        # no ping
         .rule(meta.l4_proto == "udp", udp.dport == 53, verdict=DROP))   # no DNS
chain.install()
try:
    print("outside the cgroup:", subprocess.run(cmd, capture_output=True).returncode)
    inside = subprocess.run(cmd, capture_output=True,
                            preexec_fn=lambda: (cg / "cgroup.procs").write_text(str(os.getpid())))
    print("inside the cgroup :", inside.returncode)
    for i, (rule, counters) in enumerate(zip(chain.rules, chain.counters().rules)):
        print(f"  rule {i} {rule.matchers} -> {rule.verdict}: {counters}")
finally:
    chain.flush()
    cg.rmdir()
