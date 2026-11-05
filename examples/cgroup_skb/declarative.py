#!/usr/bin/env python3
"""A whole chain in one expression, alive only inside a `with` block.

    sudo python3 examples/cgroup_skb/declarative.py

- Chain(..., sets={...}, rules=[...]): declare the sets by name, and rules that
  use them with SetRef("name"), before any of it exists in bpfilter;
- with bpyfilter.setup(): libbpfilter for the block (explicit, with options);
- with Chain(...) as fw: the chain is in bpfilter inside the block, and
  removed when it ends, even on an error;
- fw.sets["blocked"]: the chain's set, by name; change it, push it in place.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # examples/_lab.py
from _lab import ping, scratch_cgroup, show
import bpyfilter
from bpyfilter import ACCEPT, CGROUP_SKB_EGRESS, DROP, Chain, Rule, Set, SetRef
from bpyfilter.match import ip4

ADDRESSES = ("127.0.0.2", "127.0.0.3")


def report(when, cg):
    print(f"{when:24} " + "  ".join(f"{a}: {show(ping(a, cg)):7}" for a in ADDRESSES))


with bpyfilter.setup(), scratch_cgroup("bpyfilter-declarative") as cg:
    with Chain("example_declarative", CGROUP_SKB_EGRESS(cgpath=cg), policy=ACCEPT,
               sets={"blocked": Set(ip4.daddr, ["127.0.0.2"])},
               rules=[Rule([SetRef("blocked")], verdict=DROP)]) as fw:
        report("inside the block", cg)
        fw.sets["blocked"].add("127.0.0.3")
        fw.sets["blocked"].update_chain()
        report("after sets['blocked'].add()", cg)
    report("after the block", cg)
