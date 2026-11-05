import copy
import os
import re
import shutil
import socket
import subprocess
import sys
import uuid
from ipaddress import ip_address, ip_network
from pathlib import Path

import pytest

import bpyfilter
from bpyfilter import BpfilterError, Chain, Hook, Matcher, Op, Rule, Set, SetRef, Verdict
from bpyfilter.match import icmp, ip4, ip6, key, meta, tcp, udp

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


# --- no daemon needed: everything below is checked before anything is sent -------

def raw(*matchers):
    return list(Rule(matchers, verdict=Verdict.DROP).matchers)


def test_importing_does_not_start_libbpfilter():
    code = "import bpyfilter, bpyfilter.match; print(bpyfilter.is_setup())"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.stdout.strip() == "False", out.stderr


def test_the_three_spellings_are_the_same_matcher():
    assert raw("ip4.daddr eq 1.1.1.1") == raw((Matcher.IP4_DADDR, Op.EQ, "1.1.1.1")) \
        == raw(ip4.daddr == "1.1.1.1") == raw(("ip4.daddr", "eq", "1.1.1.1")) \
        == [("ip4.daddr", "eq", "1.1.1.1", False)]


def test_enums_and_fields_come_from_libbpfilter():
    assert Hook.CGROUP_SKB_EGRESS == "BF_HOOK_CGROUP_SKB_EGRESS"  # StrEnums: strings still work
    assert {"ACCEPT", "DROP", "CONTINUE", "REDIRECT", "NEXT"} <= set(Verdict.__members__)
    assert set(Op.__members__) == {"EQ", "ANY", "ALL", "IN", "RANGE"}   # "not" is a flag, not an op
    assert Matcher.IP4_DADDR == "ip4.daddr" and ip4.daddr.type is Matcher.IP4_DADDR
    for field in (meta.l4_proto, ip6.saddr, tcp.flags, udp.dport, icmp.type):
        assert isinstance(field.type, Matcher)


def test_every_hook_and_verdict_is_also_top_level():
    from bpyfilter import ACCEPT, CGROUP_SKB_EGRESS, CONTINUE, DROP, XDP
    assert (ACCEPT, DROP, CONTINUE) == (Verdict.ACCEPT, Verdict.DROP, Verdict.CONTINUE)
    assert (CGROUP_SKB_EGRESS, XDP) == (Hook.CGROUP_SKB_EGRESS, Hook.XDP)
    assert all(getattr(bpyfilter, m.name) is m for enum in (Hook, Verdict) for m in enum)
    assert {"ACCEPT", "DROP", "CGROUP_SKB_EGRESS"} <= set(bpyfilter.__all__)
    assert Chain("c", CGROUP_SKB_EGRESS, policy=DROP).policy is Verdict.DROP
    assert not hasattr(bpyfilter, "CGROUP_EGRESS")                # bpfilter 0.6's name: gone


@pytest.mark.parametrize("value, text", [
    ("1.1.1.1", "1.1.1.1"),
    (ip_address("1.1.1.1"), "1.1.1.1"),
    (ip_address("::1"), "::1"),
    (ip_network("10.0.0.0/8"), "10.0.0.0/8"),
    (443, "443"),
    (socket.IPPROTO_ICMP, "1"),                                     # an IntEnum: its number
])
def test_payloads(value, text):
    assert (ip4.daddr == value).payload == text


def test_operators():
    assert raw(tcp.dport != 22) == [("tcp.dport", "eq", "22", True)]
    assert raw(tcp.dport.range(1024, 65535)) == [("tcp.dport", "range", "1024-65535", False)]
    assert raw(tcp.flags.any("syn", "ack")) == [("tcp.flags", "any", "syn,ack", False)]
    assert raw(tcp.flags.all("syn", "ack")) == [("tcp.flags", "all", "syn,ack", False)]


def test_invert_negates_any_matcher():
    assert (~(ip4.daddr == "1.1.1.1")).negate and not (~(ip4.daddr != "1.1.1.1")).negate
    assert raw(~tcp.dport.range(1, 1023)) == [("tcp.dport", "range", "1-1023", True)]
    assert raw(~tcp.flags.any("syn")) == [("tcp.flags", "any", "syn", True)]


@pytest.mark.parametrize("text, expected", [
    ("tcp.dport not eq 22", ("tcp.dport", "eq", "22", True)),
    ("tcp.dport not range 1-1023", ("tcp.dport", "range", "1-1023", True)),
    ("tcp.dport not 22", ("tcp.dport", "eq", "22", True)),               # bfcli's short form of not eq
    (("tcp.dport", "eq", 22, True), ("tcp.dport", "eq", "22", True)),    # a tuple with negate
])
def test_negation_spellings(text, expected):
    assert raw(text) == [expected]


def test_sets_can_be_negated():
    chain = Chain("c", Hook.CGROUP_SKB_EGRESS)
    blocked = chain.add_set("blocked", ip4.daddr, ["1.1.1.1"])
    for rule in (~blocked, ~ip4.daddr.isin(blocked), "(ip4.daddr) not in blocked"):
        chain.rule(rule, verdict=Verdict.DROP)
    chain.rule(~ip4.saddr.isin(["10.0.0.1"]), verdict=Verdict.DROP)
    _, rules = chain._resolve_sets()
    assert [r[0] for r in rules] == [[("set", "(ip4.daddr)", "blocked", True)]] * 3 \
        + [[("set", "(ip4.saddr)", "{10.0.0.1}", True)]]


def test_update_set_errors_and_local_elements():
    chain = Chain("c", Hook.CGROUP_SKB_EGRESS)
    blocked = chain.add_set("blocked", ip4.daddr, ["1.1.1.1", ip_address("8.8.8.8")])
    with pytest.raises(ValueError, match="no set named 'nope'"):
        chain.update_set("nope", add=["1.2.3.4"])
    with pytest.raises(ValueError, match="needs elements"):
        chain.update_set(blocked)
    chain.update_set(blocked, add=["9.9.9.9", "1.1.1.1"], remove=["8.8.8.8"])   # not installed: local
    assert blocked._text() == "{1.1.1.1; 9.9.9.9}"


def test_a_set_is_a_python_set():
    s = Set(ip4.daddr, ["1.1.1.1", ip_address("8.8.8.8")], name="s")
    assert "8.8.8.8" in s and ip_address("1.1.1.1") in s and "9.9.9.9" not in s   # compared as text
    assert len(s) == 2 and list(s) == ["1.1.1.1", ip_address("8.8.8.8")]
    s.add("9.9.9.9"); s.add("9.9.9.9")
    s.discard("1.1.1.1"); s.discard("1.1.1.1")
    with pytest.raises(KeyError):
        s.remove("1.1.1.1")
    s.update(["10.0.0.1"], ["10.0.0.2"])
    s -= {"10.0.0.1"}
    s |= {"10.0.0.3"}
    assert s._text() == "{8.8.8.8; 9.9.9.9; 10.0.0.2; 10.0.0.3}"
    assert (s | {"1.2.3.4"}) == {ip_address("8.8.8.8"), "9.9.9.9", "10.0.0.2", "10.0.0.3", "1.2.3.4"}
    s.clear()
    assert len(s) == 0
    with pytest.raises(TypeError, match="not a truth value"):
        bool(s)


def test_pending_changes_cancel_out():
    s = Set(ip4.daddr, ["1.1.1.1"], name="s")
    s.add("2.2.2.2"); s.discard("2.2.2.2")              # added, then removed: nothing to push
    s.discard("1.1.1.1"); s.add("1.1.1.1")              # removed, then re-added: nothing to push
    assert (s._added, s._removed) == ({}, {})
    s.add("3.3.3.3"); s.discard("1.1.1.1")
    assert (list(s._added.values()), list(s._removed.values())) == (["3.3.3.3"], ["1.1.1.1"])
    with pytest.raises(ValueError, match="doesn't belong to a chain yet"):
        s.update_chain()                                # unowned: nowhere to push
    s.bind(Chain("c", Hook.XDP))
    s.update_chain()                                    # owned, chain not installed: marks it pushed
    assert (s._added, s._removed) == ({}, {})


def test_redirect_needs_a_target_and_only_with_redirect():
    with pytest.raises(ValueError, match="needs redirect="):
        Chain("c", Hook.TC_INGRESS).rule(ip4.proto == "icmp", verdict=Verdict.REDIRECT)
    with pytest.raises(ValueError, match="only goes with verdict=REDIRECT"):
        Chain("c", Hook.TC_INGRESS).rule(ip4.proto == "icmp", verdict=Verdict.DROP, redirect=("lo", "egress"))
    chain = Chain("c", Hook.TC_INGRESS).rule(ip4.proto == "icmp", verdict=Verdict.REDIRECT, redirect=("lo", "egress"))
    assert chain.rules[0].redirect == ("lo", "out")                 # libbpfilter says "in" / "out"


def test_a_matcher_is_not_a_truth_value():
    with pytest.raises(TypeError, match="not a truth value"):
        not (ip4.daddr == "1.1.1.1")
    with pytest.raises(TypeError, match="not a truth value"):
        if Set(ip4.daddr, ["1.1.1.1"], name="blocked"):
            pass


def test_rules_are_frozen_and_hashable():
    import dataclasses
    rule = Rule([ip4.proto == "icmp", "tcp.dport eq 22"], verdict=Verdict.DROP)
    assert rule.matchers == (("ip4.proto", "eq", "icmp", False), ("tcp.dport", "eq", "22", False))
    with pytest.raises(dataclasses.FrozenInstanceError):
        rule.verdict = Verdict.ACCEPT
    assert hash(rule) == hash(Rule(["ip4.proto eq icmp", tcp.dport == 22], verdict="DROP"))
    blocked = Set(ip4.daddr, ["1.1.1.1"], name="blocked")
    assert Rule([blocked], verdict=Verdict.DROP).sets == (blocked,)      # sets: kept, not hashed
    hash(Rule([blocked], verdict=Verdict.DROP))


def test_no_instance_dicts():
    from bpyfilter import Key, Match
    blocked = Set(ip4.daddr, ["1.1.1.1"], name="blocked")
    for obj in (Chain("c", Hook.XDP), Rule([ip4.proto == "icmp"], verdict=Verdict.DROP), Chain("c", Hook.XDP).sets,
                ip4.proto == "icmp", key(ip4.daddr), blocked, ip4.daddr.isin(blocked), SetRef("x")):
        assert not hasattr(obj, "__dict__"), type(obj).__name__


def test_verdict_is_required():
    with pytest.raises(TypeError, match="verdict"):
        Chain("c", Hook.XDP).rule(ip4.proto == "icmp")
    with pytest.raises(TypeError, match="verdict"):
        Rule([ip4.proto == "icmp"])


def test_a_rule_needs_a_matcher():
    with pytest.raises(ValueError, match="no catch-all rule"):
        Chain("c", Hook.XDP).rule(verdict=Verdict.ACCEPT)


@pytest.mark.parametrize("hook", [Hook.CGROUP_SKB_EGRESS, "BF_HOOK_CGROUP_SKB_EGRESS", "CGROUP_SKB_EGRESS"])
def test_hook_by_member_value_or_name(hook):
    assert Chain("c", hook).hook is Hook.CGROUP_SKB_EGRESS


def test_unknown_names():
    with pytest.raises(ValueError, match="unknown Hook 'BF_HOOK_NOPE', one of: XDP"):
        Chain("c", "BF_HOOK_NOPE")
    with pytest.raises(ValueError, match="unknown Verdict 'MAYBE'"):
        Chain("c", Hook.XDP, policy="MAYBE")
    with pytest.raises(ValueError, match="unknown matcher 'ip9.daddr'"):
        raw(("ip9.daddr", "eq", "1.1.1.1"))
    with pytest.raises(ValueError, match="unknown Op 'lol'"):
        raw(("ip4.daddr", "lol", "1.1.1.1"))


def test_sets_in_every_spelling():
    chain = Chain("c", Hook.CGROUP_SKB_EGRESS)
    blocked = chain.add_set("blocked", ip4.daddr, [ip_address("1.1.1.1"), "8.8.8.8"])
    svc = chain.add_set("svc", (ip4.daddr, tcp.dport), [("1.1.1.1", 443), ("8.8.8.8", 53)])
    chain.rule(blocked, verdict=Verdict.DROP)
    chain.rule(ip4.daddr.isin(blocked), verdict=Verdict.DROP)
    chain.rule("(ip4.daddr) in blocked", verdict=Verdict.DROP)
    chain.rule(svc, verdict=Verdict.DROP)
    chain.rule(ip4.saddr.isin(["10.0.0.1", "10.0.0.2"]), verdict=Verdict.DROP)
    chain.rule(key(ip4.daddr, tcp.dport).isin([("10.0.0.1", 22)]), verdict=Verdict.DROP)
    sets, rules = chain._resolve_sets()
    assert sets == [("blocked", "(ip4.daddr)", "{1.1.1.1; 8.8.8.8}", 0),       # the chain's named sets
                    ("svc", "(ip4.daddr, tcp.dport)", "{1.1.1.1, 443; 8.8.8.8, 53}", 0)]
    assert [r[0] for r in rules] == [[("set", "(ip4.daddr)", "blocked", False)]] * 3 + [
        [("set", "(ip4.daddr, tcp.dport)", "svc", False)],
        [("set", "(ip4.saddr)", "{10.0.0.1; 10.0.0.2}", False)],              # inline: owned by the matcher
        [("set", "(ip4.daddr, tcp.dport)", "{10.0.0.1, 22}", False)]]


def test_a_set_used_in_a_rule_joins_the_chain():
    allowed = Set(ip4.dnet, [ip_network("10.0.0.0/8")], name="allowed")
    chain = Chain("c", Hook.CGROUP_SKB_EGRESS).rule(allowed, verdict=Verdict.ACCEPT)
    assert chain.sets["allowed"] is allowed and allowed.chain is chain
    with pytest.raises(ValueError, match="already has a set named 'allowed'"):
        chain.rule(Set(ip4.dnet, ["192.168.0.0/16"], name="allowed"), verdict=Verdict.ACCEPT)


def test_a_set_in_a_rule_needs_a_name():
    with pytest.raises(ValueError, match="needs a name to join chain 'c'.*isin"):
        Chain("c", Hook.CGROUP_SKB_EGRESS).rule(Set(ip4.daddr, ["1.1.1.1"]), verdict=Verdict.DROP)
    chain = Chain("c", Hook.CGROUP_SKB_EGRESS)
    chain.sets["named_here"] = Set(ip4.daddr, ["1.1.1.1"])          # the name can come from the chain
    assert chain.sets["named_here"].name == "named_here"


def test_chain_from_sets_and_rules_with_setref():
    chain = Chain("c", Hook.CGROUP_SKB_EGRESS, policy=Verdict.ACCEPT,
                  sets={"blocked": Set(ip4.daddr, ["1.1.1.1"]), "svc": Set((ip4.daddr, tcp.dport), [("1.1.1.1", 443)])},
                  rules=[Rule([SetRef("blocked")], verdict=Verdict.DROP),
                         Rule([~SetRef("svc")], verdict=Verdict.DROP),
                         Rule([ip4.daddr.isin(SetRef("blocked"))], verdict=Verdict.DROP)])
    sets, rules = chain._resolve_sets()
    assert [n for n, _, _, _ in sets] == ["blocked", "svc"]
    assert [r[0] for r in rules] == [[("set", "(ip4.daddr)", "blocked", False)],
                                     [("set", "(ip4.daddr, tcp.dport)", "svc", True)],
                                     [("set", "(ip4.daddr)", "blocked", False)]]
    with pytest.raises(ValueError, match="has no set named 'nope'"):
        Chain("c", Hook.XDP).rule(SetRef("nope"), verdict=Verdict.DROP)._resolve_sets()
    with pytest.raises(ValueError, match=r"has key \(ip4.daddr\), not \(ip4.saddr\)"):
        chain.rule(ip4.saddr.isin(SetRef("blocked")), verdict=Verdict.DROP)._resolve_sets()
    with pytest.raises(TypeError, match="rules= takes Rule objects"):
        Chain("c", Hook.XDP, rules=["ip4.proto eq icmp"])


def test_chain_sets_by_name_and_position():
    chain = Chain("c", Hook.CGROUP_SKB_EGRESS)
    a = chain.add_set("a", ip4.daddr, ["1.1.1.1"])
    b = chain.add_set("b", ip4.saddr)
    assert chain.sets["a"] is a and chain.sets[1] is b and chain.sets[-1] is b
    assert list(chain.sets) == [a, b] and chain.sets.names() == ["a", "b"] and len(chain.sets) == 2
    assert "a" in chain.sets and a in chain.sets and Set(ip4.daddr, name="a") not in chain.sets
    chain.sets["a"].add("2.2.2.2")
    assert "2.2.2.2" in a
    chain.rule(a, verdict=Verdict.DROP)
    with pytest.raises(ValueError, match=r"is used by rule\(s\) \[0\]"):
        del chain.sets["a"]
    del chain.sets["b"]                                   # unused: fine
    assert chain.sets.names() == ["a"] and b.chain is None
    with pytest.raises(KeyError, match="has no set named 'b'"):
        chain.sets["b"]


def test_a_set_has_one_owner():
    first, second = Chain("first", Hook.XDP), Chain("second", Hook.XDP)
    s = first.add_set("s", ip4.daddr, ["1.1.1.1"])
    with pytest.raises(ValueError, match="already belongs to chain 'first'"):
        second.rule(s, verdict=Verdict.DROP)
    s.unbind()
    s.bind(second)
    assert s.chain is second and "s" in second.sets and "s" not in first.sets


def test_rules_put_straight_into_chain_rules_bind_their_sets():
    chain = Chain("c", Hook.CGROUP_SKB_EGRESS)
    s = Set(ip4.daddr, ["1.1.1.1"], name="later")
    chain.rules.append(Rule([s], verdict=Verdict.DROP))           # bypassing chain.rule()
    sets, _ = chain._resolve_sets()
    assert s.chain is chain and sets[0][0] == "later"


@pytest.mark.parametrize("make_rule, message", [
    (lambda chain, s: chain.rule("(ip4.daddr) in nope", verdict=Verdict.DROP).install(), "no set named 'nope'"),
    (lambda chain, s: chain.rule("(ip4.saddr) in blocked", verdict=Verdict.DROP).install(), "set 'blocked' has key"),
    (lambda chain, s: ip4.saddr.isin(s), r"keyed on \(ip4.daddr\), not \(ip4.saddr\)"),
])
def test_set_errors(make_rule, message):
    chain = Chain("c", Hook.CGROUP_SKB_EGRESS)
    blocked = chain.add_set("blocked", ip4.daddr, ["1.1.1.1"])
    with pytest.raises(ValueError, match=message):
        make_rule(chain, blocked)


@pytest.mark.parametrize("rule, message", [
    ("ip9.proto eq icmp", "unknown matcher"),
    ("ip4.proto lol icmp", "unknown operator"),
    ("ip4.daddr eq not-an-ip", "invalid payload"),
    (ip4.daddr == "not-an-ip", "invalid payload"),
])
def test_libbpfilter_validates_payloads(rule, message):
    with pytest.raises(ValueError, match=message):
        Chain("c", Hook.XDP).rule(rule, verdict=Verdict.DROP).install()


def test_a_hook_called_with_its_options():
    from bpyfilter import CGROUP_SKB_EGRESS, NF_LOCAL_IN, XDP, HookSpec
    spec = NF_LOCAL_IN(priorities=(101, 102))
    assert isinstance(spec, HookSpec) and spec.hook is Hook.NF_LOCAL_IN
    assert str(spec) == "BF_HOOK_NF_LOCAL_IN{priorities=101-102}"     # bfcli's text
    assert repr(spec) == "NF_LOCAL_IN(priorities=(101, 102))"
    assert NF_LOCAL_IN(priorities=[101, 102]) == spec and hash(spec)  # frozen, lists become tuples
    assert str(XDP(ifindex="lo")) == f"BF_HOOK_XDP{{ifindex={socket.if_nametoindex('lo')}}}"
    assert str(CGROUP_SKB_EGRESS(cgpath=Path("/sys/fs/cgroup/x"))) == "BF_HOOK_CGROUP_SKB_EGRESS{cgpath=/sys/fs/cgroup/x}"
    assert str(NF_LOCAL_IN()) == "BF_HOOK_NF_LOCAL_IN"                # no options: the bare hook
    assert Hook("BF_HOOK_XDP") is XDP and Hook["XDP"] is XDP           # the enum still looks members up


def test_hook_options_are_checked_where_they_are_written():
    from bpyfilter import NF_LOCAL_IN, XDP
    assert repr(XDP(ifindex="no-such-interface"))                     # names are looked up at install()
    with pytest.raises(ValueError, match="XDP doesn't take .*XDP and TC_\\* take ifindex="):
        XDP(cgpath="/sys/fs/cgroup")
    for bad in (dict(priorities=(101, 101)), dict(priorities=(0, 1)), dict(bogus=1)):
        with pytest.raises(ValueError):
            NF_LOCAL_IN(**bad)
    with pytest.raises(TypeError):
        XDP(2)                                                        # options are keywords


def test_a_chain_takes_a_hook_with_its_options():
    from bpyfilter import NF_LOCAL_IN
    chain = Chain("c", NF_LOCAL_IN(priorities=(101, 102))).rule(ip4.proto == "icmp", verdict=Verdict.DROP)
    assert chain.hook is Hook.NF_LOCAL_IN
    assert str(chain).startswith("chain c BF_HOOK_NF_LOCAL_IN{priorities=101-102} ACCEPT\n")
    assert str(Chain("c", NF_LOCAL_IN)).startswith("chain c BF_HOOK_NF_LOCAL_IN ACCEPT")
    assert str(Chain("c", NF_LOCAL_IN())).startswith("chain c BF_HOOK_NF_LOCAL_IN ACCEPT")


@pytest.mark.parametrize("how", [copy.copy, copy.deepcopy])
def test_a_copied_chain_is_its_own(how):
    from bpyfilter import NF_LOCAL_OUT
    chain = Chain("c", NF_LOCAL_OUT(priorities=(101, 102)))
    blocked = chain.add_set("blocked", ip4.daddr, ["127.0.0.2"])
    chain.rule(blocked, verdict=Verdict.DROP)
    chain._installed = True                                  # as if install() ran

    twin = how(chain)
    mine = twin.sets["blocked"]
    assert str(twin) == str(chain)                           # same content, hook options included
    assert twin.rules is not chain.rules and mine is not blocked
    assert mine.chain is twin and twin.rules[0]._uses(mine) and not twin.rules[0]._uses(blocked)
    assert not twin._installed                               # a new definition: install() sends it
    mine.add("127.0.0.3")
    twin.rule(ip4.proto == "icmp", verdict=Verdict.DROP)
    assert sorted(blocked) == ["127.0.0.2"] and len(chain.rules) == 1


def test_a_copied_set_is_unowned():
    chain = Chain("c", Hook.XDP)
    blocked = chain.add_set("blocked", ip4.daddr, ["127.0.0.2"])
    twin = copy.copy(blocked)
    assert twin.chain is None and twin.name == "blocked" and list(twin) == ["127.0.0.2"]
    assert Chain("other", Hook.XDP).rule(twin, verdict=Verdict.DROP).sets["blocked"] is twin


def test_hook_option_conveniences():
    from bpyfilter.chain import _hookopts
    assert _hookopts({"ifindex": "lo"}) == {"ifindex": socket.if_nametoindex("lo")}   # names -> index
    assert _hookopts({"ifindex": "3"}) == {"ifindex": "3"}
    assert _hookopts({"priorities": (101, 102)}) == {"priorities": "101-102"}
    assert _hookopts({"cgpath": Path("/sys/fs/cgroup/x")}) == {"cgpath": "/sys/fs/cgroup/x"}
    with pytest.raises(OSError):
        _hookopts({"ifindex": "no-such-interface"})


def test_str_is_bfcli_text():
    chain = Chain("fw", Hook.NF_LOCAL_IN, policy=Verdict.ACCEPT)
    blocked = chain.add_set("blocked", ip4.daddr, ["1.1.1.1", ip_address("8.8.8.8")])
    chain.sets["empty"] = Set(ip4.saddr)
    chain.rule(ip4.proto == "icmp", icmp.type == "echo-request", verdict=Verdict.DROP)
    chain.rule(~blocked, tcp.dport != 22, verdict=Verdict.CONTINUE, log=("internet", "transport"), counters=False)
    chain.rule(key(ip4.daddr, tcp.dport).isin([("1.1.1.1", 443)]), verdict=Verdict.DROP, log=True)
    assert str(chain) == chain.to_bfcli() == """\
chain fw BF_HOOK_NF_LOCAL_IN ACCEPT
    set blocked (ip4.daddr) in { 1.1.1.1; 8.8.8.8 }
    set empty (ip4.saddr) in {}
    rule
        ip4.proto eq icmp
        icmp.type eq echo-request
        counter
        DROP
    rule
        (ip4.daddr) not in blocked
        tcp.dport not eq 22
        log internet,transport
        CONTINUE
    rule
        (ip4.daddr, tcp.dport) in { 1.1.1.1, 443 }
        log
        counter
        DROP"""
    assert chain.to_bfcli(priorities=(101, 102)).startswith("chain fw BF_HOOK_NF_LOCAL_IN{priorities=101-102} ACCEPT\n")
    assert Chain("r", Hook.TC_INGRESS).rule(ip4.proto == "icmp", verdict="REDIRECT", redirect=("eth1", "egress")) \
        .to_bfcli().endswith("REDIRECT eth1 out")


def test_blank_set_elements_never_reach_libbpfilter():
    for elements in ([" "], ["1.1.1.1", ""], [(" ", " ")]):
        with pytest.raises(ValueError, match="can't be blank"):
            Chain("c", Hook.XDP).rule(ip4.daddr.isin(elements), verdict=Verdict.DROP).install()


def test_min_size_and_set_names():
    chain = Chain("c", Hook.XDP)
    chain.add_set("grows", ip4.saddr, ["1.1.1.1"], min_size=1024)
    assert chain._resolve_sets()[0] == [("grows", "(ip4.saddr)", "{1.1.1.1}", 1024)]
    assert "    set grows (ip4.saddr) min-size=1024 in { 1.1.1.1 }" in str(chain)
    for bad in ("has space", "dots.too", ""):
        with pytest.raises(ValueError, match="invalid set name"):
            Set(ip4.saddr, name=bad) if bad else chain.add_set(bad, ip4.saddr)


def test_port_ranges_in_sets_are_expanded():
    ports = Set(tcp.dport, [22, "27-29", range(40, 42)], name="ports")
    assert [int(p) for p in ports] == [22, 27, 28, 29, 40, 41]       # what libbpfilter stores too
    assert 28 in ports and "27-29" in ports and range(40, 42) in ports and 30 not in ports
    ports.discard(28)
    ports -= {"40-41"}
    assert [int(p) for p in ports] == [22, 27, 29]
    svc = Set((ip4.daddr, tcp.dport), [("10.0.0.1", "1-3")], name="svc")   # composite: left to libbpfilter
    assert list(svc) == [("10.0.0.1", "1-3")]


def test_log_layers():
    from bpyfilter.chain import _log_mask
    assert Rule([ip4.proto == "icmp"], verdict=Verdict.DROP, log="5-tuple").log == ("5-tuple",)
    assert _log_mask(True) == 0xFF and _log_mask(False) == 0     # bfcli's bare `log`: everything
    assert _log_mask(("internet", "transport")) == 0b110
    with pytest.raises(ValueError, match="unknown log layer"):
        Rule([ip4.proto == "icmp"], verdict=Verdict.DROP, log="headers")


# --- integration: root + libbpfilter (no daemon) --------------------------------

def _daemon_up():
    if os.geteuid() != 0:
        return False
    try:
        bpyfilter.get(f"probe-{uuid.uuid4().hex}")
    except BpfilterError as e:
        return e.errno == 2  # ENOENT: libbpfilter answered "no such chain"
    return True


needs_bpfilter = pytest.mark.skipif(not _daemon_up(), reason="needs root and bpfilter 0.8")


@pytest.fixture
def cgroup():
    cg = Path("/sys/fs/cgroup") / f"bpyfilter-test-{uuid.uuid4().hex[:8]}"
    cg.mkdir()
    yield cg
    cg.rmdir()


def _ping(cgroup=None, address="127.0.0.1"):
    pre = (lambda: (cgroup / "cgroup.procs").write_text(str(os.getpid()))) if cgroup else None
    cmd = ["ping", "-c1", "-W1", address]
    return subprocess.run(cmd, capture_output=True, preexec_fn=pre).returncode == 0


@needs_bpfilter
def test_cgroup_firewall(cgroup):
    chain = Chain(f"test-{uuid.uuid4().hex[:8]}", Hook.CGROUP_SKB_EGRESS).rule(ip4.proto == "icmp", verdict=Verdict.DROP)
    chain.install(cgpath=str(cgroup))
    try:
        assert _ping()                  # outside the cgroup: allowed
        assert not _ping(cgroup)        # inside: dropped
        counters = chain.counters()
        assert counters.attached
        assert counters.hook == Hook.CGROUP_SKB_EGRESS
        assert counters.rules[0][0] >= 1
    finally:
        chain.flush()
    assert _ping(cgroup)                # flushed: allowed again


@needs_bpfilter
def test_set_firewall(cgroup):
    chain = Chain(f"test-{uuid.uuid4().hex[:8]}", Hook.CGROUP_SKB_EGRESS)
    blocked = chain.add_set("blocked", ip4.daddr, ["127.0.0.2", ip_address("127.0.0.3")])
    chain.rule(blocked, verdict=Verdict.DROP).install(cgpath=str(cgroup))
    try:
        assert _ping(cgroup, "127.0.0.1")              # not in the set
        assert not _ping(cgroup, "127.0.0.2")          # in the set: dropped
        assert not _ping(cgroup, "127.0.0.3")
        assert _ping(None, "127.0.0.2")                # outside the cgroup: allowed
        assert chain.counters().rules[0][0] == 2
    finally:
        chain.flush()


@needs_bpfilter
def test_missing_chain():
    with pytest.raises(BpfilterError) as err:
        bpyfilter.get(f"missing-{uuid.uuid4().hex}")
    assert err.value.errno == 2


@needs_bpfilter
@pytest.mark.parametrize("example, expected", [
    ("cgroup_skb/blocklist.py", [r"127\.0\.0\.1\s+outside: ok\s+inside: ok", r"127\.0\.0\.2\s+outside: ok\s+inside: BLOCKED",
                      r"blocked \(packets, bytes\): \(2, \d+\)"]),
    ("cgroup_skb/allowlist.py", [r"127\.0\.0\.1\s+inside: ok", r"127\.0\.0\.2\s+inside: BLOCKED",
                      r"dropped by the policy: \(2, \d+\)"]),
    ("cgroup_skb/not_in_set.py", [r"127\.0\.0\.1\s+inside: ok", r"127\.0\.0\.2\s+inside: BLOCKED",
                       r"127\.0\.0\.3\s+inside: ok"]),
    ("cgroup_skb/traffic_meter.py", [r"icmp\s+3 packets", r"udp\s+5 packets", r"total\s+8 packets"]),
    ("cgroup_skb/declarative.py", [r"inside the block\s+127\.0\.0\.2: BLOCKED\s+127\.0\.0\.3: ok",
                        r"after sets\[.blocked.\]\.add\(\)\s+127\.0\.0\.2: BLOCKED\s+127\.0\.0\.3: BLOCKED",
                        r"after the block\s+127\.0\.0\.2: ok\s+127\.0\.0\.3: ok"]),
    ("cgroup_skb/update_set.py", [r"before\s+127\.0\.0\.2: BLOCKED\s+127\.0\.0\.3: ok\s+127\.0\.0\.4: ok",
                       r"changed, not pushed\s+127\.0\.0\.2: BLOCKED\s+127\.0\.0\.3: ok",
                       r"after update_chain\(\)\s+127\.0\.0\.2: ok\s+127\.0\.0\.3: BLOCKED\s+127\.0\.0\.4: ok",
                       r"auto_update: add\(\)\s+127\.0\.0\.2: ok\s+127\.0\.0\.3: BLOCKED\s+127\.0\.0\.4: BLOCKED"]),
    ("cgroup_skb/tcp_ports.py", [r":8080\s+outside: ok\s+inside: ok", r":9090\s+outside: ok\s+inside: BLOCKED",
                      r":2222\s+outside: ok\s+inside: BLOCKED"]),
    ("cgroup_sock_addr/connect4.py", [r"CGROUP_SKB_EGRESS\s+TimeoutError",
                                      r"CGROUP_SOCK_ADDR_CONNECT4\s+PermissionError: Operation not permitted after 0\.\d"]),
    ("cgroup_sock_addr/per_pid.py", [r"\(in the rule\)\s+PermissionError: Operation not permitted",
                                     r"pid \d+\s+connected"]),
    ("cgroup_sock_addr/sendmsg4.py", [r"udp/7000\s+sendto: sent\s+arrived: yes",
                                      r"udp/7001\s+sendto: PermissionError.*arrived: no"]),
    ("xdp/drop_ping.py", [r"XDP on bpyf0\s+ping: BLOCKED\s+tcp: ok", r"after\s+ping: ok"]),
    ("xdp/blocklist.py", [r"one banned\s+from 10\.250\.0\.2: ok\s+from 10\.250\.0\.3: BLOCKED",
                          r"both banned\s+from 10\.250\.0\.2: BLOCKED\s+from 10\.250\.0\.3: BLOCKED"]),
    ("tc/ingress_ports.py", [r":8080\s+from the namespace: ok", r":9090\s+from the namespace: BLOCKED"]),
    ("tc/egress_ping.py", [r"drop outgoing echo-request\s+host -> ns: BLOCKED\s+ns -> host: ok",
                           r"drop all outgoing icmp\s+host -> ns: BLOCKED\s+ns -> host: BLOCKED"]),
    ("netfilter/no_ping.py", [r"installed\s+ns -> host: BLOCKED\s+host -> 127\.0\.0\.1: BLOCKED\s+tcp: ok",
                              r"after\s+ns -> host: ok"]),
    ("netfilter/local_out.py", [r"127\.0\.0\.1\s+ok", r"127\.0\.0\.2\s+BLOCKED",
                                r"blocked \(packets, bytes\): \(2, \d+\)"]),
])
def test_examples(example, expected):
    result = subprocess.run([sys.executable, str(EXAMPLES / example)], capture_output=True, text=True,
                            timeout=120, cwd=EXAMPLES)
    assert result.returncode == 0, result.stdout + result.stderr
    for pattern in expected:
        assert re.search(pattern, result.stdout), f"{pattern!r} not in:\n{result.stdout}"


@needs_bpfilter
def test_negated_set_firewall(cgroup):
    """~blocked really inverts: only addresses NOT in the set get through."""
    chain = Chain(f"test-{uuid.uuid4().hex[:8]}", Hook.CGROUP_SKB_EGRESS, policy=Verdict.ACCEPT)
    allowed = chain.add_set("allowed", ip4.daddr, ["127.0.0.1"])
    chain.rule(~allowed, ip4.proto == "icmp", verdict=Verdict.DROP).install(cgpath=str(cgroup))
    try:
        assert _ping(cgroup, "127.0.0.1")              # in the set: not matched, allowed
        assert not _ping(cgroup, "127.0.0.2")          # not in the set: dropped
    finally:
        chain.flush()


@needs_bpfilter
def test_setup_explicit_or_on_first_use():
    code = """
import bpyfilter
from bpyfilter import Chain, Hook
print(bpyfilter.is_setup())                       # not yet
try:
    bpyfilter.get("nope")                         # the first chain operation starts it
except bpyfilter.BpfilterError:
    pass
print(bpyfilter.is_setup())
bpyfilter.teardown(); print(bpyfilter.is_setup())
bpyfilter.setup(bpffs_path="/sys/fs/bpf")         # explicit, with options
try:
    bpyfilter.setup()
except bpyfilter.BpfilterError as e:
    print("twice:", e.errno)
"""
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.stdout.split() == ["False", "True", "False", "twice:", "16"], out.stdout + out.stderr


@needs_bpfilter
def test_update_set_in_place(cgroup):
    chain = Chain(f"test-{uuid.uuid4().hex[:8]}", Hook.CGROUP_SKB_EGRESS)
    blocked = chain.add_set("blocked", ip4.daddr, ["127.0.0.2"])
    chain.rule(blocked, verdict=Verdict.DROP).install(cgpath=str(cgroup))
    try:
        assert not _ping(cgroup, "127.0.0.2") and _ping(cgroup, "127.0.0.3")
        chain.update_set(blocked, add=[ip_address("127.0.0.3")], remove=["127.0.0.2"])
        assert _ping(cgroup, "127.0.0.2") and not _ping(cgroup, "127.0.0.3")
        assert chain.counters().attached
        assert blocked._text() == "{127.0.0.3}"                 # the local set follows
        listed = subprocess.run(["bfcli", "chain", "get", "--name", chain.name], capture_output=True, text=True)
        assert "127.0.0.3" in listed.stdout and "127.0.0.2" not in listed.stdout
    finally:
        chain.flush()


@needs_bpfilter
def test_update_set_on_a_loaded_chain():
    chain = Chain(f"test-{uuid.uuid4().hex[:8]}", Hook.CGROUP_SKB_EGRESS)
    blocked = chain.add_set("blocked", ip4.daddr, ["127.0.0.2"])
    chain.rule(blocked, verdict=Verdict.DROP).install()                  # loaded, not attached
    try:
        chain.update_set(blocked, add=["127.0.0.3"])
        listed = subprocess.run(["bfcli", "chain", "get", "--name", chain.name], capture_output=True, text=True)
        assert "127.0.0.2" in listed.stdout and "127.0.0.3" in listed.stdout
    finally:
        chain.flush()


@needs_bpfilter
def test_update_replaces_rules_in_place(cgroup):
    chain = Chain(f"test-{uuid.uuid4().hex[:8]}", Hook.CGROUP_SKB_EGRESS)
    chain.rule(ip4.daddr == "127.0.0.2", verdict=Verdict.DROP).install(cgpath=str(cgroup))
    try:
        assert not _ping(cgroup, "127.0.0.2") and _ping(cgroup, "127.0.0.3")
        chain.rules.clear()
        chain.rule(ip4.daddr == "127.0.0.3", verdict=Verdict.DROP).update()
        assert _ping(cgroup, "127.0.0.2") and not _ping(cgroup, "127.0.0.3")
        counters = chain.counters()
        assert counters.attached and counters.rules[0][0] == 1      # still attached; its new rule counted
    finally:
        chain.flush()


@needs_bpfilter
def test_update_works_on_a_loaded_chain_and_needs_an_existing_one():
    chain = Chain(f"test-{uuid.uuid4().hex[:8]}", Hook.CGROUP_SKB_EGRESS)
    chain.rule(ip4.daddr == "127.0.0.2", verdict=Verdict.DROP).install()   # loaded, not attached
    try:
        chain.rules.clear()
        chain.rule(ip4.daddr == "127.0.0.3", verdict=Verdict.DROP).update()
        listed = subprocess.run(["bfcli", "chain", "get", "--name", chain.name], capture_output=True, text=True)
        assert "127.0.0.3" in listed.stdout and not chain.counters().attached
    finally:
        chain.flush()
    with pytest.raises(BpfilterError) as err:
        Chain(f"missing-{uuid.uuid4().hex[:8]}", Hook.XDP).rule(ip4.proto == "icmp", verdict=Verdict.DROP).update()
    assert err.value.errno == 2                                      # ENOENT


@needs_bpfilter
def test_set_changes_reach_the_chain_with_update_chain(cgroup):
    chain = Chain(f"test-{uuid.uuid4().hex[:8]}", Hook.CGROUP_SKB_EGRESS)
    blocked = chain.add_set("blocked", ip4.daddr, ["127.0.0.2"])
    chain.rule(blocked, verdict=Verdict.DROP).install(cgpath=str(cgroup))
    try:
        blocked.add("127.0.0.3")
        blocked.discard("127.0.0.2")
        assert not _ping(cgroup, "127.0.0.2")              # not pushed yet: still the old set
        dropped = chain.counters().rules[0]
        blocked.update_chain()
        assert chain.counters().rules[0] == dropped         # a set update keeps the counters
        assert _ping(cgroup, "127.0.0.2") and not _ping(cgroup, "127.0.0.3")
    finally:
        chain.flush()


@needs_bpfilter
def test_set_with_auto_update(cgroup):
    chain = Chain(f"test-{uuid.uuid4().hex[:8]}", Hook.CGROUP_SKB_EGRESS)
    blocked = chain.add_set("blocked", ip4.daddr, ["127.0.0.2"], auto_update=True)
    blocked.add("127.0.0.4")                                # before install(): local only, no error
    chain.rule(blocked, verdict=Verdict.DROP).install(cgpath=str(cgroup))
    try:
        assert not _ping(cgroup, "127.0.0.4")
        blocked.add("127.0.0.3")                            # each mutation pushes
        assert not _ping(cgroup, "127.0.0.3")
        blocked -= {"127.0.0.2", "127.0.0.4"}
        assert _ping(cgroup, "127.0.0.2") and _ping(cgroup, "127.0.0.4")
    finally:
        chain.flush()


@needs_bpfilter
def test_with_chain_removes_it_when_the_block_ends(cgroup):
    name = f"test-{uuid.uuid4().hex[:8]}"
    with Chain(name, Hook.CGROUP_SKB_EGRESS, sets={"blocked": Set(ip4.daddr, ["127.0.0.2"])},
               rules=[Rule([SetRef("blocked")], verdict=Verdict.DROP)]).install(cgpath=str(cgroup)) as fw:
        assert not _ping(cgroup, "127.0.0.2")
        fw.sets["blocked"].add("127.0.0.3")
        fw.sets["blocked"].update_chain()
        assert not _ping(cgroup, "127.0.0.3")
    with pytest.raises(BpfilterError) as err:            # gone from bpfilter
        bpyfilter.get(name)
    assert err.value.errno == 2
    assert _ping(cgroup, "127.0.0.2")


@needs_bpfilter
def test_with_setup():
    code = """
import bpyfilter
with bpyfilter.setup(bpffs_path="/sys/fs/bpf") as ctx:
    print(bpyfilter.is_setup())
print(bpyfilter.is_setup())
"""
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.stdout.split() == ["True", "False"], out.stdout + out.stderr


@needs_bpfilter
@pytest.mark.skipif(not shutil.which("bfcli"), reason="needs bfcli")
def test_str_round_trips_through_bfcli():
    name = f"strtest-{uuid.uuid4().hex[:8]}"
    chain = Chain(name, Hook.XDP, policy=Verdict.ACCEPT, sets={"lan": Set(ip4.dnet, ["10.0.0.0/8"])})
    blocked = chain.add_set("blocked", ip4.daddr, ["1.1.1.1", "8.8.8.8"])
    chain.add_set("empty", ip4.saddr)
    chain.rule(blocked, verdict=Verdict.DROP, log=True)
    chain.rule(~blocked, tcp.dport.range(1, 1023), verdict=Verdict.CONTINUE, log=("internet", "transport"))
    chain.rule(SetRef("lan"), udp.dport == 53, verdict=Verdict.ACCEPT, counters=False)
    chain.rule(ip4.saddr.isin(["10.0.0.1", "10.0.0.2"]), tcp.flags.any("syn", "ack"), verdict=Verdict.DROP)

    def bfcli(*args):
        return subprocess.run(["bfcli", *args], capture_output=True, text=True, timeout=30, check=True).stdout

    with chain.install():                                   # loaded, not attached: counters stay 0
        by_bpyfilter = bfcli("chain", "get", "--name", name)
    try:
        bfcli("chain", "set", "--from-str", str(chain))
        assert bfcli("chain", "get", "--name", name) == by_bpyfilter
    finally:
        bpyfilter.flush(name)


def _bfcli(*args):
    return subprocess.run(["bfcli", *args], capture_output=True, text=True, timeout=30, check=True).stdout


@needs_bpfilter
@pytest.mark.skipif(not shutil.which("bfcli"), reason="needs bfcli")
def test_load_gives_back_the_same_chain():
    name = f"loadtest-{uuid.uuid4().hex[:8]}"
    chain = Chain(name, Hook.NF_LOCAL_IN, policy=Verdict.ACCEPT, sets={"lan": Set(ip4.dnet, ["10.0.0.0/8"])})
    blocked = chain.add_set("blocked", ip4.daddr, ["1.1.1.1", "8.8.8.8"], min_size=64)
    chain.add_set("svc", (ip4.daddr, tcp.dport), [("10.0.0.1", 443)])
    chain.rule(ip4.proto == "icmp", icmp.type == "echo-request", verdict=Verdict.DROP)
    chain.rule(blocked, verdict=Verdict.DROP, log=True)
    chain.rule(~blocked, tcp.dport.range(1, 1023), tcp.flags.any("syn", "ack"), verdict=Verdict.CONTINUE,
               log=("internet", "transport"))
    chain.rule(SetRef("svc"), verdict=Verdict.DROP, counters=False)
    chain.rule(SetRef("lan"), udp.dport == 53, verdict=Verdict.ACCEPT)
    chain.rule(ip4.saddr.isin(["10.0.0.1", "10.0.0.2"]), verdict=Verdict.DROP)
    chain.rule(key(ip4.daddr, tcp.dport).isin([("1.1.1.1", 443)]), verdict=Verdict.DROP)
    with chain.install(priorities=(101, 102)):
        before = _bfcli("chain", "get", "--name", name)
        fw = Chain.load(name)
        assert fw.hook == Hook.NF_LOCAL_IN and fw.sets.names() == ["lan", "blocked", "svc"]
        assert fw.sets["blocked"].min_size == 64 and list(fw.sets["svc"]) == [("10.0.0.1", "443")]
        assert str(fw).splitlines()[0] == f"chain {name} BF_HOOK_NF_LOCAL_IN{{priorities=101-102}} ACCEPT"
        assert str(fw) == str(chain)
        fw.install(priorities=(101, 102))                  # the loaded chain builds the same programs
        assert _bfcli("chain", "get", "--name", name) == before
        fw.sets["blocked"].add("9.9.9.9")                  # and it's live: change it in place
        fw.sets["blocked"].update_chain()
        assert "9.9.9.9" in _bfcli("chain", "get", "--name", name)


@needs_bpfilter
@pytest.mark.skipif(not shutil.which("bfcli"), reason="needs bfcli")
def test_load_a_chain_made_by_bfcli():
    name = f"loadtest-{uuid.uuid4().hex[:8]}"
    _bfcli("chain", "set", "--from-str", f"""chain {name} BF_HOOK_TC_INGRESS ACCEPT
        set ports (tcp.dport) in {{ 22; 27-29 }}
        rule
            (tcp.dport) in ports
            DROP
        rule
            ip4.proto eq icmp
            REDIRECT lo out""")
    try:
        fw = Chain.load(name)
        assert [int(p) for p in fw.sets["ports"]] == [22, 27, 28, 29]
        assert fw.rules[1].redirect == (socket.if_nametoindex("lo"), "out")
        assert fw.rules[0].counters is False and fw.counters().rules == [None, None]
    finally:
        bpyfilter.flush(name)
    _bfcli("chain", "set", "--from-str", f"chain {name} BF_HOOK_TC_INGRESS ACCEPT rule ip4.proto eq icmp mark 0x1 ACCEPT")
    try:
        with pytest.raises(ValueError, match="rule 0: uses mark 0x1, which bpyfilter can't express"):
            Chain.load(name)
    finally:
        bpyfilter.flush(name)


@needs_bpfilter
def test_install_attaches_with_the_hooks_options():
    from bpyfilter import NF_LOCAL_IN
    name = f"hooktest-{uuid.uuid4().hex[:8]}"
    rules = [Rule([ip4.daddr == "192.0.2.1"], verdict=Verdict.DROP)]
    with Chain(name, NF_LOCAL_IN(priorities=(101, 102)), rules=rules).install() as fw:
        assert fw.counters().attached
        fw.install(priorities=(103, 104))                             # explicit options win, and stay
        assert fw.counters().attached
        assert str(fw).startswith(f"chain {name} BF_HOOK_NF_LOCAL_IN{{priorities=103-104}} ACCEPT")
    with Chain(name, NF_LOCAL_IN, rules=rules).install() as fw:        # no options anywhere: loaded only
        assert not fw.counters().attached


@needs_bpfilter
def test_copy_of_a_template_resets_the_installed_chain():
    from bpyfilter import NF_LOCAL_OUT
    name = f"copytest-{uuid.uuid4().hex[:8]}"
    template = Chain(name, NF_LOCAL_OUT(priorities=(101, 102)))
    template.rule(template.add_set("blocked", ip4.daddr, ["192.0.2.1"]), verdict=Verdict.DROP)

    live = copy.copy(template).install()
    try:
        live.sets["blocked"].add("192.0.2.2")
        live.sets["blocked"].update_chain()                  # the live chain drifts...
        assert "192.0.2.2" in Chain.load(name).sets["blocked"]
        copy.copy(template).install()                        # ...and goes back to the template
        assert list(Chain.load(name).sets["blocked"]) == ["192.0.2.1"]
        assert list(template.sets["blocked"]) == ["192.0.2.1"] and not template._installed
    finally:
        bpyfilter.flush(name)


@needs_bpfilter
def test_a_set_added_after_install_says_to_update():
    from bpyfilter import NF_LOCAL_OUT
    name = f"latetest-{uuid.uuid4().hex[:8]}"
    chain = Chain(name, NF_LOCAL_OUT(priorities=(101, 102)))
    chain.rule(ip4.daddr == "192.0.2.1", verdict=Verdict.DROP)
    with chain.install():
        late = chain.add_set("late", ip4.daddr, [], auto_update=True)
        with pytest.raises(ValueError, match="joined chain .* after it was installed.*chain.update\\(\\) sends it"):
            late.add("192.0.2.2")
        assert "192.0.2.2" in late                           # kept locally
        chain.update()                                       # sends the set...
        late.add("192.0.2.3")                                # ...and from then on, changes push in place
        assert sorted(Chain.load(name).sets["late"]) == ["192.0.2.2", "192.0.2.3"]


@needs_bpfilter
def test_with_chain_installs_it_for_the_block():
    from bpyfilter import NF_LOCAL_OUT
    name = f"withtest-{uuid.uuid4().hex[:8]}"
    rules = [Rule([ip4.daddr == "192.0.2.1"], verdict=Verdict.DROP)]
    with Chain(name, NF_LOCAL_OUT(priorities=(101, 102)), rules=rules) as fw:   # no install() needed
        assert fw._installed and fw.counters().attached
    with pytest.raises(BpfilterError):
        bpyfilter.get(name)                                  # gone after the block
    chain = Chain(name, NF_LOCAL_OUT, rules=rules)
    with chain.install(priorities=(103, 104)):               # already installed: entering keeps it
        assert str(Chain.load(name)).startswith(f"chain {name} BF_HOOK_NF_LOCAL_OUT{{priorities=103-104}}")
    assert not chain._installed

