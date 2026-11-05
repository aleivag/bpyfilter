"""bpyfilter: Python bindings for bpfilter (https://bpfilter.io).

bpfilter turns filtering rules into BPF programs and attaches them to a hook:
XDP, TC, netfilter, or a cgroup. bpyfilter builds those rules from Python and
hands them to libbpfilter.

    from bpyfilter import ACCEPT, CGROUP_SKB_EGRESS, DROP, Chain
    from bpyfilter.match import ip4

    chain = Chain("no_ping", CGROUP_SKB_EGRESS(cgpath="/sys/fs/cgroup/myapp"), policy=ACCEPT)
    chain.rule(ip4.proto == "icmp", verdict=DROP)
    chain.install()                     # every process in that cgroup: no ping

    chain.counters()        # ChainCounters(rules=[(1, 98)], policy=(3, 206), ...)
    chain.flush()

A matcher can be written three ways, freely mixed:

    ip4.daddr == "1.1.1.1"                       # bpyfilter.match fields
    "ip4.daddr eq 1.1.1.1"                       # bfcli's text
    (Matcher.IP4_DADDR, Op.EQ, "1.1.1.1")        # enums, for code that builds rules

Sets match many values at once (a hash map, or a trie for networks):

    blocked = chain.add_set("blocked", ip4.daddr, ["1.1.1.1", "8.8.8.8"])
    chain.rule(blocked, verdict=DROP)                             # "(ip4.daddr) in blocked"
    chain.rule(ip4.saddr.isin(["10.0.0.1", "10.0.0.2"]), verdict=DROP)   # inline
    blocked.add("9.9.9.9"); blocked.update_chain()                # changed in place

Or the whole chain in one expression, installed for the block and removed when it ends:

    with bpyfilter.setup():
        with Chain("fw", CGROUP_SKB_EGRESS(cgpath=cg), sets={"blocked": Set(ip4.daddr, ["1.1.1.1"])},
                   rules=[Rule([SetRef("blocked")], verdict=DROP)]) as fw:
            fw.sets["blocked"].add("8.8.8.8"); fw.sets["blocked"].update_chain()

Hooks and verdicts are enums (Hook.CGROUP_SKB_EGRESS, Verdict.DROP) read from
the installed libbpfilter, and every member is also importable on its own
(CGROUP_SKB_EGRESS, DROP). A hook called with its options says where to attach,
as bfcli's BF_HOOK_NF_LOCAL_IN{priorities=101-102} does:
NF_LOCAL_IN(priorities=(101, 102)), XDP(ifindex="eth0"),
CGROUP_SKB_EGRESS(cgpath=...). Nothing is attached until install().

Needs bpfilter 0.8 and root (or CAP_BPF + CAP_NET_ADMIN): there is no daemon any
more, libbpfilter generates and loads the BPF programs from this process. It
starts on the first chain operation, or explicitly with options:

    bpyfilter.setup(bpffs_path="/sys/fs/bpf", with_bpf_token=False, verbose=0)
    ...
    bpyfilter.teardown()            # also runs at exit; chains stay attached
    with bpyfilter.setup(): ...     # the same, as a block

Importing bpyfilter never starts it.

Modules: bpyfilter.chain (Chain, Rule), bpyfilter.match (fields, Match, parse),
bpyfilter.sets (Set, SetRef, ChainSets, Key, SetMatch), bpyfilter.enums (Hook,
Verdict, Matcher, Op);
everything public is re-exported here.
"""

from bpyfilter._core import BpfilterError, is_setup, setup, teardown
from bpyfilter.chain import Chain, ChainCounters, Rule, flush, flush_all, get
from bpyfilter.enums import Hook, HookSpec, Matcher, Op, Verdict
from bpyfilter.match import Match
from bpyfilter.sets import ChainSets, Key, Set, SetMatch, SetRef, key

__all__ = ["BpfilterError", "Chain", "ChainCounters", "ChainSets", "Hook", "HookSpec", "Key", "Match", "Matcher", "Op",
           "Rule", "Set", "SetMatch", "SetRef", "Verdict", "flush", "flush_all", "get", "is_setup", "key",
           "setup", "teardown"]

# Every hook and verdict at the top level too: `from bpyfilter import CGROUP_SKB_EGRESS, ACCEPT, DROP`.
globals().update({name: m for enum in (Hook, Verdict) for name, m in enum.__members__.items()})
__all__ += [name for enum in (Hook, Verdict) for name in enum.__members__]
