"""Matchers as Python expressions, generated from the installed libbpfilter.

    from ipaddress import ip_address, ip_network
    from bpyfilter.match import ip4, tcp, key

    ip4.daddr == "1.1.1.1"                       # eq
    ip4.daddr != ip_address("1.1.1.1")           # not eq   (same as ~(ip4.daddr == ...))
    ip4.dnet == ip_network("10.0.0.0/8")
    tcp.dport.range(1024, 65535)                 # range
    tcp.flags.any("syn", "ack")                  # any / all
    ip4.daddr.isin(["1.1.1.1", "8.8.8.8"])       # an inline set
    key(ip4.daddr, tcp.dport).isin([("1.1.1.1", 443)])
    ~tcp.dport.range(1024, 65535)                # ~ negates any matcher, sets included

Every field libbpfilter knows becomes `family.name` (ip4.daddr, meta.l4_proto,
icmp.type...); `Matcher` / `Op` (bpyfilter.enums) are the same names as enums.
Payloads are turned into text with str() and parsed by libbpfilter, so strings,
numbers and ipaddress objects all work.

A matcher is a rule's condition, not a truth value: Python turns `not`, `and`,
`or` and `if` into plain bools, so they can't build rules and using one raises
TypeError. Negate with ~ (or !=); pass several matchers to Chain.rule() to
require all of them. (In bpfilter, negation is a flag on any matcher, not an
operator: "tcp.dport not eq 22", "(ip4.daddr) not in blocked".)
"""

import re
from dataclasses import dataclass
from types import SimpleNamespace

from bpyfilter._base import Condition, payload
from bpyfilter.enums import Matcher, Op, matcher_type, member
from bpyfilter.sets import Key, Set, SetMatch, SetRef, key


@dataclass(frozen=True, eq=False, slots=True)
class Match(Condition):
    """`type [not] op payload`, e.g. ip4.daddr eq 1.1.1.1, tcp.dport not range 1-1023."""

    type: Matcher
    op: Op
    payload: str
    negate: bool = False

    def __invert__(self):
        return Match(self.type, self.op, self.payload, not self.negate)

    def __str__(self):
        return f"{self.type} {'not ' if self.negate else ''}{self.op} {self.payload}"

    def _raw(self):
        return (str(self.type), str(self.op), self.payload, self.negate)


class Field:
    """One matcher type, e.g. ip4.daddr: comparing it builds a Match."""

    __slots__ = ("type",)

    def __init__(self, type_):
        self.type = type_

    def __eq__(self, value):
        return Match(self.type, Op.EQ, payload(value))

    def __ne__(self, value):
        return Match(self.type, Op.EQ, payload(value), negate=True)

    def __hash__(self):
        return hash(self.type)

    def range(self, start, end):
        """start <= field <= end (ports)."""
        return Match(self.type, Op.RANGE, f"{payload(start)}-{payload(end)}")

    def any(self, *values):
        """At least one of `values` (TCP flags)."""
        return Match(self.type, Op.ANY, ",".join(map(payload, values)))

    def all(self, *values):
        """Every one of `values` (TCP flags)."""
        return Match(self.type, Op.ALL, ",".join(map(payload, values)))

    def isin(self, values):
        """A match against a Set, a SetRef, or `values` (an inline set)."""
        return SetMatch(Key((self.type,)), values)

    def __repr__(self):
        return str(self.type)


_SET_TEXT = re.compile(r"^\((?P<key>[^)]*)\)\s+(?P<negate>not\s+)?in\s+(?P<target>.+)$", re.S)


def parse(m):
    """Any of the three spellings -> (type, op, payload, negate), or ("set", key, target, negate).

    m: an expression (ip4.daddr == ...), a Set, SetRef or set match, bfcli's text
    ("type [not] op payload", "(key) [not] in name"), or (type, op, payload[, negate]).
    A set's target is a Set (by identity), a set name, or inline elements "{...}"."""
    if isinstance(m, (Match, Set, SetMatch, SetRef)):
        return m._raw()
    if isinstance(m, str) and (match := _SET_TEXT.match(m.strip())):
        # "(key) [not] in name" or "(key) [not] in {elements}": resolved in Chain.install()
        set_key = str(key(*(f.strip() for f in match["key"].split(","))))
        return ("set", set_key, match["target"].strip(), bool(match["negate"]))
    if isinstance(m, str):
        # "type op payload", "type not op payload", or bfcli's short "type not payload" (= not eq)
        parts = m.split(maxsplit=2)
        if len(parts) != 3:
            raise ValueError(f"matcher {m!r} should be 'type [not] op payload'")
        mtype, op, rest = parts
        if op != "not":
            return (mtype, op, rest, False)
        op, _, value = rest.partition(" ")
        if op in Op.__members__.values() and value.strip():
            return (mtype, op, value.strip(), True)
        return (mtype, "eq", rest, True)
    if isinstance(m, tuple) and len(m) in (3, 4):
        mtype, op, value, *negate = m
        return (str(matcher_type(mtype)), str(member(Op, op)), payload(value), bool(negate and negate[0]))
    raise ValueError(f"matcher {m!r} should be an expression (ip4.daddr == ...), "
                     f"'type [not] op payload', or (type, op, payload[, negate])")


# One namespace per family: ip4.daddr, tcp.dport, meta.l4_proto, icmp.type, ...
_families = {}
for _m in Matcher:
    _family, _, _name = _m.value.partition(".")
    _families.setdefault(_family, {})[_name] = Field(_m)
globals().update({family: SimpleNamespace(**fields) for family, fields in _families.items()})

# Key, Set, SetMatch and key live in bpyfilter.sets; also here, since `key` reads like a field helper.
__all__ = ["Field", "Key", "Match", "Matcher", "Op", "Set", "SetMatch", "SetRef", "key", "parse",
           "payload", *_families]
