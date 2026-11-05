"""Sets: match a packet against many values at once (a hash map, or a trie for networks).

    blocked = Set(ip4.daddr, ["1.1.1.1", ip_address("8.8.8.8")], name="blocked")
    chain.rule(blocked, verdict=DROP)                  # (ip4.daddr) in blocked
    chain.rule(~blocked, verdict=ACCEPT)               # (ip4.daddr) not in blocked
    blocked.add("9.9.9.9"); blocked.update_chain()     # change it in place

    Chain(..., sets={"foo": Set(ip4.daddr, [...])}).rule(SetRef("foo"), verdict=DROP)

A Set is a matcher and a Python set, owned by at most one chain: unowned until it
joins one (chain.rule(), chain.add_set(), Chain(sets=...), chain.sets[name] = s,
s.bind(chain, name)). It needs a name to join (bpfilter updates sets in place by
name): for a fixed list of values, use an inline set, field.isin([...]).
SetRef("name") refers to a set the chain declares, before you have the object. chain.sets is the chain's sets, by
name or by position. Key is the field(s) a set is keyed on; SetMatch is
field.isin(...).
"""

import re
from collections.abc import MutableSet
from dataclasses import dataclass

from bpyfilter._base import Condition, element_key, elements_text
from bpyfilter.enums import matcher_type


@dataclass(frozen=True, slots=True)
class Key:
    """The field(s) a set is keyed on: (ip4.daddr), or (ip4.daddr, tcp.dport)."""

    fields: tuple

    def isin(self, values):
        """A match against a Set, a SetRef, or `values` (an inline set)."""
        return SetMatch(self, values)

    def __str__(self):
        return "(" + ", ".join(self.fields) + ")"


def key(*fields):
    """A composite key for inline sets: key(ip4.daddr, tcp.dport).isin([...])."""
    if not fields:
        raise ValueError("a set key needs at least one field")
    return Key(tuple(matcher_type(f) for f in fields))


_SET_NAME = re.compile(r"^[A-Za-z0-9_-]+$")


def _check_name(name):
    """libbpfilter (0.8) only takes set names of ASCII letters, digits, underscores, hyphens."""
    if name is not None and not _SET_NAME.match(name):
        raise ValueError(f"invalid set name {name!r}: use ASCII letters, digits, '_' and '-'")
    return name


_PORT_FIELDS = {"tcp.sport", "tcp.dport", "udp.sport", "udp.dport", "meta.sport", "meta.dport"}
_PORT_RANGE = re.compile(r"^\s*(\d+)\s*-\s*(\d+)\s*$")


def _expand(key_, elements):
    """A set keyed on one port field takes ranges ("27-30", range(27, 31)): libbpfilter (0.8)
    stores each port, so the Python side does too, and `28 in s` / s.discard(28) agree."""
    if len(key_.fields) != 1 or str(key_.fields[0]) not in _PORT_FIELDS:
        yield from elements
        return
    for element in elements:
        if isinstance(element, range):
            yield from element
        elif isinstance(element, str) and (match := _PORT_RANGE.match(element)):
            yield from range(int(match[1]), int(match[2]) + 1)
        else:
            yield element


def _as_key(key_):
    return key_ if isinstance(key_, Key) else key(*(key_ if isinstance(key_, tuple) else (key_,)))


class Set(Condition, MutableSet):
    """A set of elements keyed on one or more fields: a matcher in rules, and a Python set.

        Set(ip4.daddr, ["1.1.1.1"], name="blocked", auto_update=False, min_size=0)
        Set((ip4.daddr, tcp.dport), [("10.0.0.1", 443)], name="svc")   # composite key
        Set(tcp.dport, [22, "8000-8080", range(9000, 9010)], name="ports")  # one port field: ranges

    It needs a name to join a chain: name=, or the name it's given there
    (chain.add_set(name, ...), Chain(sets={name: ...}), chain.sets[name] = s).

    Owned by at most one chain (s.chain; None while unowned). Mutate it like a set
    (add, discard, remove, update, difference_update, clear, |=, -=, `in`, len,
    iteration); update_chain() pushes the changes since the last push to its chain,
    in place (bf_chain_update_set), and auto_update=True does it on every mutation.
    While unowned, or before its chain is installed, changes are only local.
    min_size reserves room in the set's BPF map for elements added later (a lower
    bound: a bigger set gets a bigger map).

    It's not a truth value (it's a matcher, and `not blocked` would silently mean
    False): use len(s) to ask whether it's empty, ~s to negate it in a rule."""

    __slots__ = ("name", "key", "auto_update", "min_size", "_elements", "_added", "_removed", "_chain")

    def __init__(self, key, elements=(), name=None, auto_update=False, min_size=0):
        self.key = _as_key(key)
        self.name = _check_name(name)
        self.auto_update = auto_update
        self.min_size = int(min_size)
        self._elements = {}                     # comparison key -> element, in insertion order
        for element in _expand(self.key, elements):
            self._elements.setdefault(element_key(element), element)
        self._added, self._removed = {}, {}     # changes not pushed yet
        self._chain = None                      # the owning chain

    # --- ownership ------------------------------------------------------------------------
    @property
    def chain(self):
        """The chain that owns this set, or None."""
        return self._chain

    def bind(self, chain, name=None):
        """Join `chain`, as `name` (or the set's own name). One owner only."""
        chain.sets._bind(self, name)
        return self

    def unbind(self):
        """Leave the owning chain; refused while one of its rules uses this set."""
        if self._chain is not None:
            self._chain.sets._unbind(self)
        return self

    # --- a set ----------------------------------------------------------------------
    def __contains__(self, element):
        if isinstance(element, range) or (isinstance(element, str) and _PORT_RANGE.match(element)):
            return all(element_key(e) in self._elements for e in _expand(self.key, [element]))
        return element_key(element) in self._elements

    def __iter__(self):
        return iter(list(self._elements.values()))

    def __len__(self):
        return len(self._elements)

    @property
    def elements(self):
        return list(self._elements.values())

    def add(self, element):
        self._change(add=[element])

    def discard(self, element):
        self._change(remove=[element])

    def update(self, *iterables):
        """Add every element of `iterables` (one push, with auto_update)."""
        self._change(add=[e for iterable in iterables for e in iterable])

    def difference_update(self, *iterables):
        """Remove every element of `iterables` (one push, with auto_update)."""
        self._change(remove=[e for iterable in iterables for e in iterable])

    def clear(self):
        self._change(remove=self.elements)

    def __ior__(self, other):
        self.update(other)
        return self

    def __isub__(self, other):
        self.difference_update(other)
        return self

    @classmethod
    def _from_iterable(cls, iterable):
        return set(iterable)                    # a | b, a & b, a - b: plain Python sets

    # --- keeping the chain in sync -----------------------------------------------------
    def _change(self, add=(), remove=(), push=None):
        add, remove = list(_expand(self.key, add)), list(_expand(self.key, remove))
        for element in remove:
            k = element_key(element)
            if k in self._elements:
                gone = self._elements.pop(k)
                if self._added.pop(k, None) is None:     # pushed before: remove it there too
                    self._removed[k] = gone
        for element in add:
            k = element_key(element)
            if k not in self._elements:
                self._elements[k] = element
                if self._removed.pop(k, None) is None:   # not just removed: add it there
                    self._added[k] = element
        if (self.auto_update if push is None else push) and self._chain is not None:
            self.update_chain()

    def update_chain(self):
        """Push the changes since the last push to the owning chain, in place (if installed)."""
        if self._chain is None:
            raise ValueError(f"{self!r} doesn't belong to a chain yet: use it in chain.rule(), "
                             "or chain.add_set() / Chain(sets=...) / chain.sets[name] = s / s.bind(chain)")
        if self._added or self._removed:
            self._chain._push_set_changes(self, list(self._added.values()), list(self._removed.values()))
            self._synced()
        return self

    def _synced(self):
        self._added.clear()
        self._removed.clear()

    def __deepcopy__(self, memo):
        """Copied with its chain (copy.copy(chain)), it belongs to the chain's copy; copied
        alone, it's unowned: same name, key and elements, ready to join another chain."""
        new = Set.__new__(Set)
        memo[id(self)] = new
        new.name, new.key, new.auto_update, new.min_size = self.name, self.key, self.auto_update, self.min_size
        new._elements, new._added, new._removed = dict(self._elements), dict(self._added), dict(self._removed)
        new._chain = memo.get(id(self._chain))
        if new._chain is None:
            new._synced()
        return new

    def __copy__(self):
        return self.__deepcopy__({})

    # --- a matcher ------------------------------------------------------------------------
    def __invert__(self):
        """"(key) not in name"."""
        return SetMatch(self.key, self, negate=True)

    def __repr__(self):
        owner = f", chain={self._chain.name!r}" if self._chain is not None else ""
        return f"Set({self.key}, {len(self)} elements, name={self.name!r}{owner})"

    def _text(self):
        return elements_text(self.elements)

    def _raw(self):
        return ("set", str(self.key), _SetHandle(self), False)


class _SetHandle:
    """A Set inside a rule's normalized matchers: the name is only known once the set
    joins a chain, and rules (frozen, hashable) compare and hash it by identity."""

    __slots__ = ("set",)

    def __init__(self, s):
        self.set = s

    def __eq__(self, other):
        return isinstance(other, _SetHandle) and other.set is self.set

    def __hash__(self):
        return id(self.set)

    def __repr__(self):
        return f"<{self.set!r}>"


@dataclass(frozen=True, slots=True)
class SetRef(Condition):
    """A reference, by name, to a set the chain declares: usable before you have the object.

        Chain(..., sets={"foo": Set(ip4.daddr, [...])}).rule(SetRef("foo"), verdict=DROP)

    The key comes from the declared set when the chain is installed (or updated);
    install() fails if the chain declares no set by that name."""

    name: str
    negate: bool = False

    def __invert__(self):
        return SetRef(self.name, not self.negate)

    def _raw(self):
        return ("set", None, self.name, self.negate)


@dataclass(frozen=True, eq=False, slots=True)
class SetMatch(Condition):
    """field.isin(...): against a Set, a SetRef, or an inline (anonymous) set of values."""

    key: Key
    target: object
    negate: bool = False

    def __post_init__(self):
        if isinstance(self.target, Set):
            if self.target.key != self.key:
                raise ValueError(f"{self.target!r} is keyed on {self.target.key}, not {self.key}")
        elif not isinstance(self.target, SetRef):
            object.__setattr__(self, "target", list(self.target))

    def __invert__(self):
        return SetMatch(self.key, self.target, not self.negate)

    def _raw(self):
        if isinstance(self.target, Set):
            return ("set", str(self.key), _SetHandle(self.target), self.negate)
        if isinstance(self.target, SetRef):
            return ("set", str(self.key), self.target.name, self.negate != self.target.negate)
        return ("set", str(self.key), elements_text(self.target), self.negate)


class ChainSets:
    """A chain's sets: by name like a dict, by position like a tuple (libbpfilter's order).

        chain.sets["blocked"].add("1.1.1.1")     # the Set named "blocked"
        chain.sets[0]                            # the first one
        chain.sets["other"] = Set(ip4.saddr)     # bind a set under a name
        del chain.sets["other"]                  # unbind it (refused while a rule uses it)
        for s in chain.sets: ...                 # the Sets, in order; .names() for the names
    """

    __slots__ = ("_chain", "_by_name")

    def __init__(self, chain):
        self._chain = chain
        self._by_name = {}

    def __getitem__(self, item):
        if isinstance(item, int):
            return list(self._by_name.values())[item]
        try:
            return self._by_name[item]
        except KeyError:
            raise KeyError(f"chain {self._chain.name!r} has no set named {item!r}") from None

    def __setitem__(self, name, s):
        self._bind(s, name)

    def __delitem__(self, item):
        self._unbind(self[item])

    def __contains__(self, item):
        if isinstance(item, Set):
            return item._chain is self._chain
        return item in self._by_name

    def __iter__(self):
        return iter(list(self._by_name.values()))

    def __len__(self):
        return len(self._by_name)

    def names(self):
        return list(self._by_name)

    def items(self):
        return list(self._by_name.items())

    def get(self, name, default=None):
        return self._by_name.get(name, default)

    def __repr__(self):
        return f"ChainSets({self.names()})"

    def _bind(self, s, name=None):
        if not isinstance(s, Set):
            raise TypeError(f"a chain's sets are Set objects, not {type(s).__name__}")
        if s._chain is self._chain:
            if name is not None and name != s.name:
                raise ValueError(f"{s!r} is already in chain {self._chain.name!r} as {s.name!r}")
            return s
        if s._chain is not None:
            raise ValueError(f"{s!r} already belongs to chain {s._chain.name!r}: "
                             "a set has one owner (unbind() it first)")
        if name is not None and s.name is not None and name != s.name:
            raise ValueError(f"{s!r} is named {s.name!r}, not {name!r}")
        name = _check_name(name or s.name)
        if name is None:
            raise ValueError(f"{s!r} needs a name to join chain {self._chain.name!r} (bpfilter updates "
                             "sets in place by name): Set(..., name=...), chain.add_set(name, ...), "
                             "Chain(sets={name: ...}); for a fixed list of values, use field.isin([...])")
        if name in self._by_name:
            raise ValueError(f"chain {self._chain.name!r} already has a set named {name!r}")
        s.name, s._chain = name, self._chain
        self._by_name[name] = s
        return s

    def _unbind(self, s):
        if s._chain is not self._chain:
            return
        users = [i for i, rule in enumerate(self._chain.rules) if rule._uses(s)]
        if users:
            raise ValueError(f"{s!r} is used by rule(s) {users} of chain {self._chain.name!r}")
        del self._by_name[s.name]
        s._chain = None


__all__ = ["ChainSets", "Key", "Set", "SetMatch", "SetRef", "key"]
