"""Chains and their rules: what bpyfilter hands to libbpfilter.

    chain = Chain("no_ping", NF_LOCAL_IN(priorities=(101, 102)), policy=ACCEPT)
    chain.rule(ip4.proto == "icmp", verdict=DROP)
    chain.install()                                # create in bpfilter, and attach (replace=True: replace)
    chain.update()                                 # replace its rules in place, same attachment
    chain.counters(); chain.flush()
    print(chain)                                   # the same chain as bfcli's text
    print(chain.diff(other))                       # how it differs from another chain (bpfilter's: diff())
    Chain.load("no_ping")                          # a chain bpfilter has, back as a Chain
    chain.copy(name="no_ping_out", hook=NF_LOCAL_OUT)   # a new chain, not installed
    chain.clean(rules=True, sets=False)            # empty it (here: update() sends it)

    # or all at once: installed for the block, removed from bpfilter when it ends
    with Chain("fw", CGROUP_SKB_EGRESS(cgpath=cg), sets={"blocked": Set(ip4.daddr, [...])},
               rules=[Rule([SetRef("blocked")], verdict=DROP)]) as fw:
        ...

The hook can carry the options to attach to it, NF_LOCAL_IN(priorities=(101, 102)),
or be bare, NF_LOCAL_IN, with the options given to install(...) instead.

A chain's policy is what happens to every packet no rule decides; each rule needs
at least one matcher and an explicit verdict.
"""

import copy
import difflib
import errno
import math
from dataclasses import dataclass, field, fields
from typing import NamedTuple

from bpyfilter._base import elements_text
from bpyfilter._core import (
    BpfilterError,
    chain_flush,
    chain_get,
    chain_load,
    chain_set,
    chain_update,
    chain_update_set,
    check_hookopts,
    ruleset_flush,
    ruleset_names,
)
from bpyfilter.enums import Hook, HookSpec, Verdict, _hookopts, member
from bpyfilter.match import parse
from bpyfilter.sets import ChainSets, Set, SetMatch, _SetHandle, key


@dataclass(frozen=True, slots=True)
class Rule:
    """All `matchers` must match for the rule to apply its `verdict`. Immutable: to change
    a chain's rules, replace them (chain.rules) and install() or update() the chain."""

    matchers: tuple
    verdict: Verdict
    counters: bool = True
    log: object = False         # True (everything), or layers: ("internet", "transport"), "5-tuple"
    redirect: tuple = None      # (interface, "in" / "out"), for verdict=REDIRECT
    # the Sets among the matchers (the chain they join takes them); mutable, so not hashed
    sets: tuple = field(default=(), init=False, repr=False, compare=False)

    def __post_init__(self):
        if not self.matchers:
            raise ValueError("a rule needs at least one matcher: bpfilter has no catch-all rule "
                             "(the chain's policy is what happens to everything else)")
        sets = tuple(m.target if isinstance(m, SetMatch) else m for m in self.matchers
                     if isinstance(m, Set) or (isinstance(m, SetMatch) and isinstance(m.target, Set)))
        # frozen: the normalized values are set once, here
        object.__setattr__(self, "sets", sets)
        object.__setattr__(self, "matchers", tuple(parse(m) for m in self.matchers))
        object.__setattr__(self, "verdict", member(Verdict, self.verdict))
        object.__setattr__(self, "log", _log_option(self.log))
        if (self.verdict.name == "REDIRECT") != (self.redirect is not None):
            raise ValueError("verdict=REDIRECT needs redirect=(interface, 'in' or 'out'), "
                             "and redirect= only goes with verdict=REDIRECT")
        if self.redirect is not None:
            iface, direction = self.redirect
            direction = _REDIRECT_DIRS.get(direction, direction)
            if direction not in ("in", "out"):
                raise ValueError(f"redirect direction {self.redirect[1]!r}: 'in' or 'out' "
                                 "('ingress' / 'egress' work too)")
            object.__setattr__(self, "redirect", (iface, direction))

    def _uses(self, s):
        """Does this rule match against set `s` (the object, or its name)?"""
        return any(m[0] == "set" and (m[2] == _SetHandle(s) or m[2] == s.name) for m in self.matchers)

    def _set_names(self):
        """The names of the chain sets this rule matches against (not inline sets)."""
        return [m[2].set.name if isinstance(m[2], _SetHandle) else m[2] for m in self.matchers
                if m[0] == "set" and (isinstance(m[2], _SetHandle) or not m[2].startswith("{"))]

    def _with_sets(self, by_name):
        """This rule, its Set matchers pointing at the sets of `by_name` with the same names."""
        new = object.__new__(Rule)
        for f in fields(Rule):
            object.__setattr__(new, f.name, getattr(self, f.name))
        object.__setattr__(new, "matchers", tuple(
            ("set", m[1], _SetHandle(by_name[m[2].set.name]), m[3])
            if m[0] == "set" and isinstance(m[2], _SetHandle) else m for m in self.matchers))
        object.__setattr__(new, "sets", tuple(by_name[s.name] for s in self.sets))
        return new


class ChainDiff(str):
    """What Chain.diff() returns: the diff's text, shown as is in a REPL; empty (falsy) if
    the chains are the same."""

    __slots__ = ()

    def __repr__(self):
        return str(self) or "(no differences)"


class ChainCounters(NamedTuple):
    """(packets, bytes) per rule (None if the rule has no counter), policy, errors."""

    hook: str
    policy_verdict: str
    attached: bool
    rules: list
    policy: tuple
    error: tuple


@dataclass(slots=True)
class Chain:
    """A named list of rules for one hook; `policy` is what happens to everything else.

        Chain(name, hook, policy=ACCEPT, sets={"name": Set(...)}, rules=[Rule(...)])

    `hook` is a Hook (NF_LOCAL_IN), or a hook with its options (a HookSpec:
    NF_LOCAL_IN(priorities=(101, 102)), XDP(ifindex="eth0")...), which install()
    attaches with. `sets` and `rules` are optional starting points (sets declared by name, so rules
    can use SetRef("name")); chain.rule() and chain.add_set() add more. chain.sets is
    the chain's sets, by name or position; chain.rules is a list of frozen Rules.
    As a context manager, `with chain:` installs it, and removes it from bpfilter when
    the block ends."""

    name: str
    hook: Hook
    policy: Verdict = Verdict.ACCEPT
    sets: ChainSets = None
    rules: list = None
    _installed: bool = field(default=False, init=False, repr=False)   # install()/update() ran, no flush()
    _hookopts: dict = field(default_factory=dict, init=False, repr=False)   # the hook's, or the last install()'s
    _sets_in_bpfilter: set = field(default_factory=set, init=False, repr=False)   # as of the last install()/update()

    def __post_init__(self):
        if isinstance(self.hook, HookSpec):
            self.hook, self._hookopts = self.hook.hook, dict(self.hook.options)
        self.hook = member(Hook, self.hook)
        self.policy = member(Verdict, self.policy)
        given_sets, given_rules = self.sets, self.rules
        self.sets, self.rules = ChainSets(self), []
        self._bind_sets(given_sets)
        self._add_rules(given_rules)

    @classmethod
    def load(cls, name):
        """Chain `name` as bpfilter has it, whoever made it (bpyfilter, bfcli...), as an
        installed Chain: change its rules and update() it, change a set and update_chain()
        it, print() it.

            fw = Chain.load("fw")
            fw.sets["blocked"].add("9.9.9.9"); fw.sets["blocked"].update_chain()

        Payloads and set elements come back as libbpfilter prints them ("10.0.0.0/8",
        "443", "icmp"); attached chains keep their hook options (str(fw) shows them).
        Rule marks and log rate limits raise ValueError: bpyfilter can't express them."""
        hook, policy, hookopts, sets, rules = chain_load(name)
        chain = cls(name, hook, policy,
                    sets={n: Set(_key_from_text(k), elements, min_size=m) for n, k, elements, m in sets})
        for i, (matchers, verdict, counters, log, log_rate_ns, mark, redirect) in enumerate(rules):
            if mark is not None or log_rate_ns:
                what = f"mark {mark:#x}" if mark is not None else "a log rate limit"
                raise ValueError(f"chain {name!r}, rule {i}: uses {what}, which bpyfilter can't express")
            chain._add_rule(Rule(tuple(chain._loaded_matcher(m) for m in matchers), verdict, counters,
                                 _log_layers(log), redirect))
        chain._hookopts = hookopts or {}
        chain._installed_with_sets()
        return chain

    # --- building it --------------------------------------------------------------------
    def rule(self, *matchers, verdict, counters=True, log=False, redirect=None):
        """Append a rule: all `matchers` must match. Returns the chain, so calls can be chained.

        A Set used here joins the chain (it needs a name). log: True logs everything the
        hook can (`bfcli chain logs`), or some layers: "link", "internet", "transport"
        (or several, in a tuple), or "5-tuple". redirect: (interface name or index,
        "in" or "out", or "ingress" / "egress"), with verdict=REDIRECT (TC and XDP hooks;
        XDP can only redirect out)."""
        return self._add_rule(Rule(matchers, verdict, counters, log, redirect))

    def add_set(self, name, key, elements=(), auto_update=False, min_size=0) -> Set:
        """A named set, owned by this chain; returns it, to use in rules and to change later:
        rule(s, ...), rule(~s, ...), rule(ip4.daddr.isin(s), ...), s.add(...); s.update_chain().

        key: a field (ip4.daddr), or a tuple for a composite key (ip4.daddr, tcp.dport);
        elements: values, or tuples of values for a composite key. A single network
        field (ip4.dnet, ip6.snet...) takes CIDRs and becomes a longest-prefix-match trie.
        min_size: room in the set's BPF map for elements added later, with update_chain().
        Same as chain.sets[name] = Set(key, elements); rules can also use SetRef(name),
        or bfcli's text "(ip4.daddr) in name"."""
        return self.sets._bind(Set(key, elements, name=name, auto_update=auto_update, min_size=min_size))

    def _add_rule(self, rule):
        for s in rule.sets:                 # a Set used in a rule joins the chain
            self.sets._bind(s)
        self.rules.append(rule)
        return self

    def _add_rules(self, rules):
        for rule in rules or ():
            if not isinstance(rule, Rule):
                raise TypeError(f"rules= takes Rule objects, not {type(rule).__name__}: use chain.rule() "
                                "for matchers")
            self._add_rule(rule)

    def _bind_sets(self, sets):
        if isinstance(sets, dict):
            for set_name, s in sets.items():
                self.sets._bind(s, set_name)
        else:
            for s in sets or ():
                self.sets._bind(s)

    def clean(self, rules=True, sets=True):
        """Remove the chain's rules, its sets, or both (the default); returns the chain.
        Only here: update() or install() sends the change to bpfilter. Removed sets are
        unowned, free to join another chain. A set a remaining rule uses can't go:
        clean(sets=True, rules=False) raises ValueError then, and removes nothing.

            chain.clean(sets=False).rule(ip4.proto == "icmp", verdict=DROP).update()"""
        if sets and not rules:
            used = sorted({n for rule in self.rules for n in rule._set_names()} & set(self.sets.names()))
            if used:
                raise ValueError(f"chain {self.name!r}'s rules use set(s) {used}: clean() them too "
                                 "(rules=True), or remove those rules first")
        if rules:
            self.rules.clear()
        if sets:
            for s in self.sets:
                self.sets._unbind(s)
        return self

    def copy(self, name=None, hook=None, policy=None, sets=None, rules=None):
        """A copy of the chain, with its own rules and sets, not installed; the arguments,
        the constructor's, replace what they name (None keeps it):

            connect = fw.copy(name="fw_connect", hook=CGROUP_SOCK_ADDR_CONNECT4)
            other = fw.copy(name="fw2", sets={"blocked": Set(ip4.daddr, ["9.9.9.9"])})

        hook: a hook with options (a HookSpec) brings its own; a bare hook keeps the chain's
        options if it takes them (cgpath= from one CGROUP_* hook to another), and drops
        them if not (install(**hookopts) then). sets: replace all of the chain's sets; the
        rules kept point at the new sets with the same names (ValueError if one is missing).
        rules: replace all of the chain's rules. Same as copy.copy(chain) with no arguments."""
        new = copy.deepcopy(self)
        if name is not None:
            new.name = name
        if hook is not None:
            if isinstance(hook, HookSpec):
                new.hook, new._hookopts = hook.hook, dict(hook.options)
            else:
                new.hook = member(Hook, hook)
                try:
                    if new._hookopts:
                        check_hookopts(str(new.hook), _hookopts(new._hookopts, resolve_names=False))
                except ValueError:
                    new._hookopts = {}
        if policy is not None:
            new.policy = member(Verdict, policy)
        if rules is not None:
            new.rules.clear()
        if sets is not None:
            for s in new.sets:              # the copies go: rules re-point to the new sets below
                s._chain = None
            new.sets = ChainSets(new)
            new._bind_sets(sets)
            for i, rule in enumerate(new.rules):
                missing = [n for n in rule._set_names() if n not in new.sets]
                if missing:
                    raise ValueError(f"rule {i} of chain {self.name!r} uses set {missing[0]!r}, which "
                                     "sets= doesn't have: give it, or replace the rules too (rules=)")
                new.rules[i] = rule._with_sets(dict(new.sets.items()))
        new._add_rules(rules)
        return new

    # --- bpfilter ------------------------------------------------------------------------
    def install(self, replace=False, **hookopts):
        """Create the chain in bpfilter, and attach it: with `hookopts` if given, else with
        the hook's options (Chain(name, XDP(ifindex=2))) or the last install()'s. With no
        options anywhere, the chain is loaded but not attached. Returns the chain, so it
        chains: `with chain.install(ifindex=2):`.

        If bpfilter already has a chain by this name, install() raises BpfilterError
        (EEXIST) and leaves it alone, unless replace=True (bf_chain_set: the old one is
        detached and replaced), or it's this chain: installed, or loaded, by this object.
        The options each hook needs (same as the hook's):

            XDP, TC_*                   ifindex=  an interface index or name ("eth0")
            NF_*                        priorities=(101, 102)  two different, non-zero
            CGROUP_SKB_*, CGROUP_SOCK_ADDR_*   cgpath="/sys/fs/cgroup/..."
        """
        hookopts = hookopts or self._hookopts
        sets, rules = self._resolve_sets()
        try:
            chain_set(self.name, str(self.hook), str(self.policy), sets, rules, _hookopts(hookopts),
                      replace=replace or self._installed)
        except BpfilterError as e:
            if e.errno != errno.EEXIST:
                raise
            raise BpfilterError(e.errno, f"bpfilter already has a chain named {self.name!r}: "
                                "install(replace=True) replaces it, Chain.load() reads it") from None
        self._hookopts = dict(hookopts)
        self._installed_with_sets()
        return self

    def update(self):
        """Replace the rules and sets of this chain in bpfilter, keeping its attachment
        (bf_chain_update): whatever it's attached to stays. The chain must exist (install()
        creates it); counters restart from zero, as with install()."""
        sets, rules = self._resolve_sets()
        chain_update(self.name, str(self.hook), str(self.policy), sets, rules)
        self._installed_with_sets()
        return self

    def update_set(self, s, add=(), remove=()):
        """Add and/or remove elements of set `s` (a Set, or its name) in bpfilter, without
        replacing the chain: libbpfilter regenerates its program in place.

            chain.update_set(blocked, add=["1.2.3.4"], remove=[ip_address("8.8.8.8")])

        Same as s.add(...)/s.discard(...) then s.update_chain()."""
        known = self.sets.get(s if isinstance(s, str) else s.name)
        if known is None or (isinstance(s, Set) and known is not s):
            raise ValueError(f"chain {self.name!r} has no set named {s if isinstance(s, str) else s.name!r}")
        add, remove = list(add), list(remove)
        if not add and not remove:
            raise ValueError("update_set() needs elements to add or to remove")
        known._change(add, remove, push=False)
        known.update_chain()
        return self

    def to_bfcli(self, **hookopts):
        """The chain as bfcli's text, with `hookopts` (same as install()'s):

            bfcli chain set --from-str "$(python3 -c '...print(chain.to_bfcli(ifindex=2))')"

        str(chain) is the same, with the options of the last install()."""
        return "\n".join(self._bfcli_lines(hookopts))

    def __str__(self):
        return self.to_bfcli(**self._hookopts)

    def diff(self, other=None, *, context=3):
        """How this chain differs from `other`: a unified diff of their bfcli text, `other`'s
        lines with -, this chain's with + (as `git diff other this`); empty if they're the same.

            print(chain2.diff(chain1))
            chain.diff()                # against bpfilter's chain of this name: what update() changes
            chain.diff("fw")            # against bpfilter's chain "fw"
            chain.diff(context=0)       # only the changed lines
            chain.diff(context=math.inf)    # the whole chain

        context: the unchanged lines shown around each change (3, as git diff), math.inf for
        all of them. Set elements are one per line, sorted, so element order doesn't count. Hook options
        are the last install()'s (a loaded chain: what it's attached with). A loaded chain's
        values are libbpfilter's text, so 0x16 and 22 can differ where bpfilter wouldn't."""
        if not (context == math.inf or (isinstance(context, int) and not isinstance(context, bool)
                                         and context >= 0)):
            raise ValueError(f"context={context!r}: a number of lines (0 or more), or math.inf for all")
        old_label = None
        if other is None or isinstance(other, str):
            other = Chain.load(self.name if other is None else other)
            old_label = f"{other.name} (bpfilter)"
        old = other._bfcli_lines(other._hookopts, expand_sets=True)
        new = self._bfcli_lines(self._hookopts, expand_sets=True)
        if context == math.inf:
            context = max(len(old), len(new))
        return ChainDiff("\n".join(difflib.unified_diff(old, new, old_label or other.name, self.name,
                                                       n=context, lineterm="")))

    def _bfcli_lines(self, hookopts, expand_sets=False):
        """to_bfcli()'s lines; expand_sets: set elements one per line, sorted (for diff())."""
        opts = ",".join(f"{k}={v}" for k, v in _hookopts(hookopts).items())
        lines = [f"chain {self.name} {self.hook}{'{' + opts + '}' if opts else ''} {self.policy}"]
        self._bind_rule_sets()
        for s in self.sets:
            head = f"    set {s.name} {s.key}{f' min-size={s.min_size}' if s.min_size else ''} in "
            if not expand_sets or not len(s):
                lines.append(head + _braces(s._text()))
                continue
            lines.append(head + "{")
            lines += sorted(f"        {elements_text([e])[1:-1]}" for e in s.elements)
            lines.append("    }")
        for rule in self.rules:
            lines.append("    rule")
            lines += [f"        {self._matcher_text(m)}" for m in rule.matchers]
            if rule.log:
                lines.append("        log" if rule.log is True else f"        log {','.join(rule.log)}")
            if rule.counters:
                lines.append("        counter")
            if rule.redirect is not None:
                iface, direction = rule.redirect
                lines.append(f"        REDIRECT {iface} {direction}")
            else:
                lines.append(f"        {rule.verdict}")
        return lines

    def counters(self) -> ChainCounters:
        return get(self.name)

    def flush(self):
        """Detach and delete the chain (it's gone, not emptied); install() installs it again.
        Returns the chain: chain.flush().install() puts it back."""
        flush(self.name)
        self._installed = False
        self._sets_in_bpfilter = set()
        return self

    def __deepcopy__(self, memo):
        """A copy with its own rules and sets, not installed: copy.copy(template).install(replace=True)
        replaces the chain bpfilter has under this name with the template's content."""
        new = object.__new__(Chain)
        memo[id(self)] = new                # the sets' copies belong to the new chain
        for f in fields(self):
            object.__setattr__(new, f.name, copy.deepcopy(getattr(self, f.name), memo))
        new._installed, new._sets_in_bpfilter = False, set()
        for s in new.sets:                  # nothing sent yet: install() sends everything
            s._synced()
        return new

    def __copy__(self):
        """Same as copy.deepcopy(): a chain sharing its rules or sets would be half another chain."""
        return self.__deepcopy__({})

    def __enter__(self):
        """`with chain:` installs it (with the hook's options), unless it's installed already
        (`with chain.install(**hookopts):` still works)."""
        if not self._installed:
            self.install()
        return self

    def __exit__(self, *exc):
        """Leaving `with chain:` removes the chain from bpfilter, even if the block raised."""
        if self._installed:
            self.flush()
        return False

    # --- internals ----------------------------------------------------------------------
    def _push_set_changes(self, s, add, remove):
        """Called by Set.update_chain(): bf_chain_update_set, if this chain is in bpfilter."""
        if not self._installed:
            return
        if s.name not in self._sets_in_bpfilter:
            # the set joined after install(): bpfilter has never seen it, nothing to change in place
            raise ValueError(f"set {s.name!r} joined chain {self.name!r} after it was installed, so bpfilter "
                             "doesn't have it yet: chain.update() sends it (counters restart); "
                             "the change is kept locally until then")
        chain_update_set(self.name, s.name, str(s.key), elements_text(add), elements_text(remove))

    def _installed_with_sets(self):
        self._installed = True
        self._sets_in_bpfilter = set(self.sets.names())
        for s in self.sets:                 # bpfilter has exactly these elements now
            s._synced()

    def _loaded_matcher(self, matcher):
        if matcher[0] != "set":
            return matcher                  # (type, op, payload, negate)
        _, set_key, target, negate = matcher
        target = self.sets[target] if isinstance(target, str) else target   # named, or inline elements
        return SetMatch(_key_from_text(set_key), target, negate)

    def _bind_rule_sets(self):
        for rule in self.rules:             # rules put straight into chain.rules join here
            for s in rule.sets:
                self.sets._bind(s)

    def _matcher_text(self, matcher):
        mtype, op, target, negate = matcher
        not_ = "not " if negate else ""
        if mtype != "set":
            return f"{mtype} {not_}{op} {target}"
        if isinstance(target, _SetHandle):
            target = target.set.name
        set_key = op if op is not None else self.sets[target].key   # a SetRef: the declared set's key
        return f"{set_key} {not_}in {_braces(target) if target.startswith('{') else target}"

    def _resolve_sets(self):
        """What libbpfilter gets: the chain's named sets, and rules whose set matchers
        name one of them (or carry an inline set, "{...}")."""
        self._bind_rule_sets()
        sets = [(s.name, str(s.key), s._text(), s.min_size) for s in self.sets]
        rules = []
        for rule in self.rules:
            matchers = []
            for matcher in rule.matchers:
                if matcher[0] == "set":
                    _, set_key, target, negate = matcher
                    if isinstance(target, _SetHandle):          # a Set object: by identity
                        target = target.set.name
                    if not target.startswith("{"):              # not inline: one of the chain's
                        if target not in self.sets:
                            raise ValueError(f"chain {self.name!r} has no set named {target!r}: declare it "
                                             "with add_set(), Chain(sets=...) or chain.sets[name] = Set(...)")
                        declared = str(self.sets[target].key)
                        if set_key is not None and set_key != declared:
                            raise ValueError(f"set {target!r} has key {declared}, not {set_key}")
                        set_key = declared
                    matcher = ("set", set_key, target, negate)
                matchers.append(matcher)
            rules.append((matchers, str(rule.verdict), rule.counters, _log_mask(rule.log), rule.redirect))
        return sets, rules


# bf_log_opt, in order: bf_rule.log is a bitmask of them, and 0xFF (BF_LOG_OPT_DEFAULT) is
# "everything the hook can log", bfcli's bare `log`.
_LOG_LAYERS = ("link", "internet", "transport", "5-tuple")
_REDIRECT_DIRS = {"ingress": "in", "egress": "out"}


def _log_option(log):
    if log is True or not log:
        return bool(log)
    layers = (log,) if isinstance(log, str) else tuple(log)
    for layer in layers:
        if layer not in _LOG_LAYERS:
            raise ValueError(f"unknown log layer {layer!r}: log=True, or some of {', '.join(_LOG_LAYERS)}")
    return layers


def _log_layers(mask):
    """bf_rule.log -> what Rule(log=) takes."""
    if mask == 0xFF:
        return True
    return tuple(layer for i, layer in enumerate(_LOG_LAYERS) if mask & (1 << i)) or False


def _log_mask(log):
    if log is True:
        return 0xFF
    return sum(1 << _LOG_LAYERS.index(layer) for layer in log or ())


def _braces(elements):
    """"{a; b}" -> "{ a; b }", the way bfcli prints sets; an empty set is "{}"."""
    return "{ " + elements[1:-1] + " }" if elements != "{}" else "{}"


def _key_from_text(text):
    """"(ip4.daddr, tcp.dport)" -> Key."""
    return key(*(field.strip() for field in text.strip("()").split(",")))


def get(name) -> ChainCounters:
    """Counters (and hook/policy/attached state) of chain `name`."""
    return ChainCounters(*chain_get(name))


def flush(name):
    """Detach and delete chain `name`."""
    chain_flush(name)


def chains():
    """The names of every chain bpfilter has, whoever made them, sorted:
    Chain.load(name) reads one back."""
    return ruleset_names()


def flush_all():
    """Delete every chain bpfilter knows about."""
    ruleset_flush()


__all__ = ["Chain", "ChainCounters", "ChainDiff", "Rule", "chains", "flush", "flush_all", "get"]
