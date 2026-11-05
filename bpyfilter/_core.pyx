# cython: language_level=3
"""
C side of bpyfilter: turns plain Python data into libbpfilter objects, hands
them to libbpfilter, and frees everything on every path.

bpfilter has no daemon: libbpfilter itself generates the BPF
programs and loads them, from this process, once its context is set up
(bf_ctx_setup). That's setup(): called explicitly, or by the first chain
operation, never by importing bpyfilter (the enums only ask libbpfilter for
names, which touches neither the kernel nor bpffs).

Ownership rules (from libbpfilter's headers):
- bf_chain_add_set() and bf_chain_add_rule() take the set / rule on success;
- a chain owns its named sets, and a matcher owns its anonymous set (0.8);
- bf_chain_get() hands back a chain and its hookopts, which the caller frees.
"""

import atexit
import os
import socket

from libc.stdlib cimport free

from bpyfilter._libbpfilter cimport *


cdef extern from *:
    """
    #include <stdio.h>

    /* libbpfilter prints a payload as text with its print() callbacks, to stdout (that's
     * how bfcli shows chains): point stdout at a memory buffer for the call. */
    static char *bpyf_print_to_string(void (*print)(const void *), const void *payload)
    {
        char *text = NULL;
        size_t len = 0;
        FILE *saved = stdout;
        FILE *mem = open_memstream(&text, &len);

        if (!mem)
            return NULL;
        fflush(saved);
        stdout = mem;
        print(payload);
        stdout = saved;
        fclose(mem);
        return text;
    }
    """
    char *bpyf_print_to_string(bf_matcher_print_fn print_payload, const void *payload)


class BpfilterError(OSError):
    "An error returned by libbpfilter."


cdef _check(int ret, what):
    if ret < 0:
        hint = {13: " (bpfilter needs root, or CAP_BPF and CAP_NET_ADMIN)",
                1: " (bpfilter needs root, or CAP_BPF and CAP_NET_ADMIN)",
                67: " (the chain isn't attached: install() it with hook options first)"}.get(-ret, "")
        raise BpfilterError(-ret, f"{what}: {os.strerror(-ret)}{hint}")
    return ret


cdef bint _ctx_ready = False


class _Setup:
    """What setup() returns: also a context manager, `with bpyfilter.setup(...):`."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        teardown()
        return False

    def __repr__(self):
        return f"<bpyfilter setup: {'active' if _ctx_ready else 'torn down'}>"


def setup(bpffs_path="/sys/fs/bpf", with_bpf_token=False, verbose=0):
    """Start libbpfilter in this process (bf_ctx_setup): explicitly, with options.

    Optional: the first chain operation calls it with the defaults. Importing
    bpyfilter never does. bpffs_path: where the BPF objects and bpfilter's state
    are pinned; with_bpf_token: use a BPF token created from that bpffs;
    verbose: libbpfilter's verbose flags (a bitmask).

    Returns a context manager: `with bpyfilter.setup():` tears it down at the end
    (chains stay attached)."""
    global _ctx_ready
    if _ctx_ready:
        raise BpfilterError(16, "bpyfilter.setup(): already set up (bpyfilter.teardown() first)")
    ret = bf_ctx_setup(with_bpf_token, str(bpffs_path).encode(), verbose)
    if ret != -16:          # EBUSY: something else in this process already set it up
        _check(ret, "bf_ctx_setup")
        atexit.register(teardown)
    _ctx_ready = True
    return _Setup()


def teardown():
    """Stop libbpfilter in this process (bf_ctx_teardown). Chains stay attached."""
    global _ctx_ready
    if _ctx_ready:
        bf_ctx_teardown()
        _ctx_ready = False


def is_setup():
    """True once setup() ran, explicitly or on the first chain operation."""
    return _ctx_ready


cdef _ensure_ctx():
    if not _ctx_ready:
        setup()


cdef bf_hook _hook(str name) except *:
    cdef bf_hook hook
    if bf_hook_from_str(name.encode(), &hook) < 0:
        raise ValueError(f"unknown hook {name!r}")
    return hook


cdef bf_verdict _verdict(str name) except *:
    cdef bf_verdict verdict
    if bf_verdict_from_str(name.encode(), &verdict) < 0:
        raise ValueError(f"unknown verdict {name!r}")
    return verdict


cdef bf_matcher *_new_set_matcher(bf_chain *chain, key, str target, bint negate) except NULL:
    """A matcher on the chain's set named `target`, or on an inline set "{...}" (keyed `key`)."""
    cdef bf_matcher *matcher = NULL
    cdef const bf_set *named
    if target.startswith("{"):
        if bf_matcher_new_for_anon_set_from_raw(&matcher, key.encode(), target.encode(), negate) < 0:
            raise ValueError(f"invalid inline set: key {key!r}, elements {target!r}")
        return matcher
    named = bf_chain_get_set_by_name(chain, target.encode())
    if named == NULL:
        raise ValueError(f"no set named {target!r} in the chain")
    _check(bf_matcher_new_for_named_set(&matcher, named, negate), f"bf_matcher_new_for_named_set({target!r})")
    return matcher


cdef bf_rule *_new_rule(bf_chain *chain, tuple matchers, str verdict, bint counters, int log,
                        redirect) except NULL:
    """A bf_rule for `chain` from [(type, op, payload, negate), ...]; freed by the caller on error.

    ("set", key, target, negate) matches against the chain's set named `target`, or
    an inline set when `target` is "{...}" (bfcli's text).
    log: bf_rule.log, a bitmask of bf_log_opt (0xFF, BF_LOG_OPT_DEFAULT: all the hook has).
    redirect: None, or (interface name or index, "in" / "out") for REDIRECT."""
    cdef bf_rule *rule = NULL
    cdef bf_matcher *matcher = NULL
    cdef bf_matcher_type mtype
    cdef bf_matcher_op mop
    cdef bf_redirect_dir direction

    _check(bf_rule_new(&rule), "bf_rule_new")
    try:
        rule.verdict = _verdict(verdict)
        rule.has_counters = 1 if counters else 0
        rule.log = log
        if redirect is not None:
            iface, direction_s = redirect
            rule.redirect_ifindex = iface if isinstance(iface, int) else socket.if_nametoindex(iface)
            if bf_redirect_dir_from_str(str(direction_s).encode(), &direction) < 0:
                raise ValueError(f"unknown redirect direction {direction_s!r} (in or out)")
            rule.redirect_dir = direction
        for mtype_s, op_s, payload, negate in matchers:
            if mtype_s == "set":
                matcher = _new_set_matcher(chain, op_s, payload, negate)
            else:
                if bf_matcher_type_from_str(mtype_s.encode(), &mtype) < 0:
                    raise ValueError(f"unknown matcher {mtype_s!r}")
                if bf_matcher_op_from_str(op_s.encode(), &mop) < 0:
                    raise ValueError(f"unknown operator {op_s!r} for {mtype_s}")
                if bf_matcher_new_from_raw(&matcher, mtype, mop, str(payload).encode(), negate) < 0:
                    raise ValueError(f"invalid payload {payload!r} for {mtype_s} {op_s}")
            _check(bf_list_add_tail(&rule.matchers, matcher), "bf_list_add_tail")
            matcher = NULL  # now owned by the rule
    except BaseException:
        bf_matcher_free(&matcher)
        bf_rule_free(&rule)
        raise
    return rule


cdef bf_set *_new_set(set_name, str key, str payload, size_t min_size=0) except NULL:
    """A bf_set from bfcli's text: key "(ip4.daddr, tcp.dport)", payload "{1.1.1.1, 443; ...}"."""
    cdef bf_set *c_set = NULL
    cdef const char *c_name = NULL
    name_b = set_name.encode() if set_name else None
    if name_b is not None:
        c_name = name_b
    if bf_set_new_from_raw(&c_set, c_name, key.encode(), payload.encode()) < 0:
        raise ValueError(f"invalid set {set_name or '(anonymous)'}: key {key!r}, elements {payload!r}")
    c_set.min_size = min_size
    return c_set


cdef bf_chain *_new_chain(str name, str hook, str policy, list sets, list rules) except NULL:
    """sets: [(name, raw key, raw elements, min_size), ...], the chain's named sets;
    rules: [(matchers, verdict, counters, log, redirect), ...]."""
    cdef bf_chain *chain = NULL
    cdef bf_rule *rule = NULL
    cdef bf_set *c_set = NULL

    _check(bf_chain_new(&chain, name.encode(), _hook(hook), _verdict(policy), NULL, NULL), "bf_chain_new")
    try:
        for set_name, key, payload, min_size in sets:
            c_set = _new_set(set_name, key, payload, min_size)
            _check(bf_chain_add_set(chain, c_set), f"bf_chain_add_set({set_name!r})")
            c_set = NULL  # now owned by the chain
        for i, (matchers, verdict, counters, log, redirect) in enumerate(rules):
            rule = _new_rule(chain, tuple(matchers), verdict, counters, log, redirect)
            ret = bf_chain_add_rule(chain, rule)
            if ret < 0:
                raise ValueError(f"rule {i}: libbpfilter refused it for {hook} ({os.strerror(-ret)})")
            rule = NULL  # now owned by the chain
    except BaseException:
        bf_rule_free(&rule)
        bf_set_free(&c_set)
        bf_chain_free(&chain)
        raise
    return chain


cdef bf_hookopts *_new_hookopts(str hook, dict opts) except NULL:
    cdef bf_hookopts *hookopts = NULL
    _check(bf_hookopts_new(&hookopts), "bf_hookopts_new")
    try:
        for key, value in opts.items():
            raw = f"{key}={value}"
            if bf_hookopts_parse_opt(hookopts, raw.encode()) < 0:
                raise ValueError(f"invalid hook option {raw!r}")
        _check(bf_hookopts_validate(hookopts, _hook(hook)), f"hook options for {hook}")
    except BaseException:
        bf_hookopts_free(&hookopts)
        raise
    return hookopts


def check_hookopts(str hook, dict opts):
    """Parse and validate hook options with libbpfilter (no kernel, no bpffs): ValueError
    for an unknown option, a bad value, or an option `hook` doesn't take."""
    cdef bf_hookopts *hookopts = NULL
    try:
        hookopts = _new_hookopts(hook, opts)
    except BpfilterError:
        raise ValueError(f"{hook.removeprefix('BF_HOOK_')} doesn't take {opts}: XDP and TC_* take "
                         "ifindex=, NF_* priorities=, CGROUP_* cgpath=") from None
    finally:
        bf_hookopts_free(&hookopts)


def chain_set(str name, str hook, str policy, list sets, list rules, dict hookopts):
    """Create or replace a chain; attach it if hookopts is non-empty.

    sets: [(name, raw key, raw elements, min_size), ...], the chain's named sets;
    rules: [(matchers, verdict, counters, log, redirect), ...],
    matchers: [(type, op, payload, negate)], or ("set", key, name or "{...}", negate).
    """
    cdef bf_chain *chain = _new_chain(name, hook, policy, sets, rules)
    cdef bf_hookopts *c_hookopts = NULL
    try:
        if hookopts:
            c_hookopts = _new_hookopts(hook, hookopts)
        _ensure_ctx()
        _check(bf_chain_set(chain, c_hookopts), f"bf_chain_set({name!r})")
    finally:
        bf_hookopts_free(&c_hookopts)
        bf_chain_free(&chain)


def chain_get(str name):
    """(hook, policy, attached, [rule counters], policy counter, error counter).

    Counters are (packets, bytes) tuples, None for rules without counters.
    """
    cdef bf_chain *chain = NULL
    cdef bf_hookopts *hookopts = NULL
    cdef bf_list_node *node
    cdef bf_rule *rule

    _ensure_ctx()
    try:
        _check(bf_chain_get(name.encode(), &chain, &hookopts), f"bf_chain_get({name!r})")
        rule_counters = []
        node = chain.rules.head
        while node != NULL:
            rule = <bf_rule *>node.data
            rule_counters.append((rule.counters.count, rule.counters.size) if rule.has_counters else None)
            node = node.next
        return (bf_hook_to_str(chain.hook).decode(), bf_verdict_to_str(chain.policy).decode(),
                hookopts != NULL, rule_counters,
                (chain.policy_counters.count, chain.policy_counters.size),
                (chain.error_counters.count, chain.error_counters.size))
    finally:
        bf_hookopts_free(&hookopts)
        bf_chain_free(&chain)


cdef str _payload_text(const bf_matcher_ops *ops, const void *payload, what):
    if ops == NULL or ops.print_payload == NULL:
        raise ValueError(f"libbpfilter can't print the payload of {what}")
    cdef char *text = bpyf_print_to_string(ops.print_payload, payload)
    if text == NULL:
        raise MemoryError()
    try:
        return text.decode()
    finally:
        free(text)


cdef tuple _set_content(const bf_set *c_set):
    """(key "(a, b)", [element, ...]): an element is the text of each component, a tuple
    for a composite key."""
    cdef const bf_matcher_ops *ops
    cdef const bf_hashset_elem *elem = c_set.elems.head
    cdef size_t offset
    fields = [bf_matcher_type_to_str(c_set.key[i]).decode() for i in range(c_set.n_comps)]
    elements = []
    while elem != NULL:
        offset = 0
        parts = []
        for i in range(c_set.n_comps):
            ops = bf_matcher_get_ops(c_set.key[i], BF_MATCHER_IN)
            parts.append(_payload_text(ops, <const char *>elem.data + offset, f"set key {fields[i]}"))
            offset += ops.ref_payload_size
        elements.append(parts[0] if len(parts) == 1 else tuple(parts))
        elem = elem.next
    return "(" + ", ".join(fields) + ")", elements


cdef _matcher_back(const bf_chain *chain, const bf_matcher *matcher):
    """(type, op, payload text, negate), or ("set", key, name, negate) for a named set and
    ("set", key, [elements], negate) for an anonymous one."""
    cdef bf_matcher_type mtype = bf_matcher_get_type(matcher)
    cdef bf_matcher_op mop = bf_matcher_get_op(matcher)
    cdef const bf_set *c_set
    negate = bool(bf_matcher_get_negate(matcher))
    if mtype == BF_MATCHER_SET:
        c_set = bf_chain_get_set_for_matcher(chain, matcher)
        if c_set == NULL:
            raise ValueError("a set matcher without its set")
        set_key, elements = _set_content(c_set)
        return ("set", set_key, c_set.name.decode() if c_set.name != NULL else elements, negate)
    type_s, op_s = bf_matcher_type_to_str(mtype).decode(), bf_matcher_op_to_str(mop).decode()
    return (type_s, op_s, _payload_text(bf_matcher_get_ops(mtype, mop), bf_matcher_payload(matcher),
                                        f"{type_s} {op_s}"), negate)


def chain_load(str name):
    """Chain `name` as bpfilter has it, whoever made it:
    (hook, policy, hookopts or None, sets, rules), with
    sets: [(name, key, [element, ...], min_size), ...];
    rules: [(matchers, verdict, counters, log mask, log_rate_ns, mark, redirect), ...];
    redirect: None or (ifindex, "in" / "out")."""
    cdef bf_chain *chain = NULL
    cdef bf_hookopts *c_hookopts = NULL
    cdef const bf_hashset_elem *elem
    cdef const bf_set *c_set
    cdef bf_list_node *rule_node
    cdef bf_list_node *matcher_node
    cdef bf_rule *rule

    _ensure_ctx()
    try:
        _check(bf_chain_get(name.encode(), &chain, &c_hookopts), f"bf_chain_get({name!r})")
        hookopts = None
        if c_hookopts != NULL:
            hookopts = {}
            if c_hookopts.used_opts & (1 << BF_HOOKOPTS_IFINDEX):
                hookopts["ifindex"] = c_hookopts.ifindex
            if c_hookopts.used_opts & (1 << BF_HOOKOPTS_CGPATH):
                hookopts["cgpath"] = c_hookopts.cgpath.decode()
            if c_hookopts.used_opts & (1 << BF_HOOKOPTS_PRIORITIES):
                hookopts["priorities"] = (c_hookopts.priorities[0], c_hookopts.priorities[1])
        sets = []
        elem = chain.sets.head
        while elem != NULL:
            c_set = <const bf_set *>elem.data
            set_key, elements = _set_content(c_set)
            sets.append((c_set.name.decode(), set_key, elements, c_set.min_size))
            elem = elem.next
        rules = []
        rule_node = chain.rules.head
        while rule_node != NULL:
            rule = <bf_rule *>rule_node.data
            matchers = []
            matcher_node = rule.matchers.head
            while matcher_node != NULL:
                matchers.append(_matcher_back(chain, <const bf_matcher *>matcher_node.data))
                matcher_node = matcher_node.next
            redirect = None
            if rule.verdict == BF_VERDICT_REDIRECT:
                redirect = (rule.redirect_ifindex, bf_redirect_dir_to_str(rule.redirect_dir).decode())
            rules.append((matchers, bf_verdict_to_str(rule.verdict).decode(), bool(rule.has_counters),
                          rule.log, rule.log_rate_ns, bf_rule_mark_get(rule) if bf_rule_mark_is_set(rule) else None,
                          redirect))
            rule_node = rule_node.next
        return (bf_hook_to_str(chain.hook).decode(), bf_verdict_to_str(chain.policy).decode(),
                hookopts, sets, rules)
    finally:
        bf_hookopts_free(&c_hookopts)
        bf_chain_free(&chain)


def chain_update(str name, str hook, str policy, list sets, list rules):
    """Replace the rules and sets of an attached chain in place (bf_chain_update): it stays
    attached where it is, and counters are kept. Same arguments as chain_set, no hookopts."""
    cdef bf_chain *chain = _new_chain(name, hook, policy, sets, rules)
    try:
        _ensure_ctx()
        _check(bf_chain_update(chain), f"bf_chain_update({name!r})")
    finally:
        bf_chain_free(&chain)


def chain_update_set(str chain_name, str set_name, str key, str to_add, str to_remove):
    """Add and remove elements of a named set in an attached chain (bf_chain_update_set):
    libbpfilter regenerates the chain's program. to_add / to_remove: bfcli's text, "{...}"."""
    cdef bf_set *c_add = NULL
    cdef bf_set *c_remove = NULL
    try:
        c_add = _new_set(set_name, key, to_add)
        c_remove = _new_set(set_name, key, to_remove)
        _ensure_ctx()
        _check(bf_chain_update_set(chain_name.encode(), c_add, c_remove),
               f"bf_chain_update_set({chain_name!r}, {set_name!r})")
    finally:
        bf_set_free(&c_add)
        bf_set_free(&c_remove)


def chain_flush(str name):
    _ensure_ctx()
    _check(bf_chain_flush(name.encode()), f"bf_chain_flush({name!r})")


def ruleset_flush():
    _ensure_ctx()
    _check(bf_ruleset_flush(), "bf_ruleset_flush")


def hook_names():
    """Every hook this libbpfilter knows, e.g. "BF_HOOK_CGROUP_SKB_EGRESS"."""
    return [bf_hook_to_str(<bf_hook>i).decode() for i in range(<int>_BF_HOOK_MAX)]


def verdict_names():
    """Every verdict this libbpfilter knows, e.g. "DROP"."""
    return [bf_verdict_to_str(<bf_verdict>i).decode() for i in range(<int>_BF_VERDICT_MAX)]


def matcher_type_names():
    """Every matcher type this libbpfilter knows, e.g. "ip4.daddr" (and "<set>")."""
    return [bf_matcher_type_to_str(<bf_matcher_type>i).decode() for i in range(<int>_BF_MATCHER_TYPE_MAX)]


def matcher_op_names():
    """Every matcher operator this libbpfilter knows, e.g. "eq"."""
    return [bf_matcher_op_to_str(<bf_matcher_op>i).decode() for i in range(<int>_BF_MATCHER_OP_MAX)]
