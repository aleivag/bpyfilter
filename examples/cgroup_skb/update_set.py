#!/usr/bin/env python3
"""Change a running blocklist: a Set is a Python set that can push its changes.

    sudo python3 examples/cgroup_skb/update_set.py

Mutate the set like any Python set, then update_chain() pushes just the changes
to the attached chain, in place (libbpfilter's bf_chain_update_set). With
auto_update=True, every mutation pushes on its own.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # examples/_lab.py
from _lab import ping, scratch_cgroup, show
from bpyfilter import ACCEPT, CGROUP_SKB_EGRESS, DROP, Chain
from bpyfilter.match import ip4

ADDRESSES = ("127.0.0.2", "127.0.0.3", "127.0.0.4")


def report(when, cg):
    print(f"{when:22} " + "  ".join(f"{a}: {show(ping(a, cg)):7}" for a in ADDRESSES))


with scratch_cgroup("bpyfilter-update-set") as cg:
    chain = Chain("example_update_set", CGROUP_SKB_EGRESS(cgpath=cg), policy=ACCEPT)
    blocked = chain.add_set("blocked", ip4.daddr, ["127.0.0.2"])
    chain.rule(blocked, verdict=DROP)
    with chain:
        report("before", cg)
        blocked.add("127.0.0.3")
        blocked.discard("127.0.0.2")
        report("changed, not pushed", cg)
        blocked.update_chain()
        report("after update_chain()", cg)
        blocked.auto_update = True
        blocked.add("127.0.0.4")
        report("auto_update: add()", cg)
        print("blocked now:", sorted(blocked))
