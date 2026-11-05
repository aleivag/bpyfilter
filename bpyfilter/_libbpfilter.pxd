# cython: language_level=3
#
# Declarations from libbpfilter's public headers (bpfilter 0.8), only what
# bpyfilter uses. Compiled against the real headers, so a mismatch is a build
# error rather than a crash.

from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t


cdef extern from "bpfilter/core/list.h":
    ctypedef void (*bf_list_ops_free)(void **data)
    ctypedef int (*bf_list_ops_pack)(const void *data, void *pack)

    ctypedef struct bf_list_ops:
        bf_list_ops_free free
        bf_list_ops_pack pack

    ctypedef struct bf_list_node:
        void *data
        bf_list_node *prev
        bf_list_node *next

    ctypedef struct bf_list:
        size_t len
        bf_list_node *head
        bf_list_node *tail
        bf_list_ops ops

    void bf_list_init(bf_list *list, const bf_list_ops *ops)
    void bf_list_clean(bf_list *list)
    int bf_list_add_tail(bf_list *list, void *data)


cdef extern from "bpfilter/logger.h":
    cdef enum bf_log_level:
        BF_LOG_INFO
        BF_LOG_WARN
    bf_log_level bf_log_get_level()
    void bf_log_set_level(bf_log_level level)


cdef extern from "bpfilter/ctx.h":
    # No daemon: the library generates and loads the BPF programs itself,
    # once its (process-wide) context is set up.
    int bf_ctx_setup(bint with_bpf_token, const char *bpffs_path, uint16_t verbose)
    void bf_ctx_teardown()


cdef extern from "bpfilter/verdict.h":
    enum bf_verdict:
        BF_VERDICT_ACCEPT
        BF_VERDICT_DROP
        BF_VERDICT_REDIRECT
        _BF_VERDICT_MAX

    enum bf_redirect_dir:
        BF_REDIRECT_INGRESS
        BF_REDIRECT_EGRESS

    const char *bf_verdict_to_str(bf_verdict verdict)
    int bf_verdict_from_str(const char *str, bf_verdict *verdict)
    int bf_redirect_dir_from_str(const char *str, bf_redirect_dir *dir)     # "in" / "out"
    const char *bf_redirect_dir_to_str(bf_redirect_dir dir)


cdef extern from "bpfilter/hook.h":
    enum bf_hook:
        BF_HOOK_XDP
        _BF_HOOK_MAX

    struct bf_hookopts:
        uint32_t used_opts           # a bit per bf_hookopts_type
        int ifindex
        const char *cgpath
        unsigned int family
        int priorities[2]

    enum bf_hookopts_type:
        BF_HOOKOPTS_IFINDEX
        BF_HOOKOPTS_CGPATH
        BF_HOOKOPTS_FAMILY
        BF_HOOKOPTS_PRIORITIES

    const char *bf_hook_to_str(bf_hook hook)
    int bf_hook_from_str(const char *str, bf_hook *hook)
    int bf_hookopts_new(bf_hookopts **hookopts)
    void bf_hookopts_free(bf_hookopts **hookopts)
    int bf_hookopts_parse_opt(bf_hookopts *hookopts, const char *raw_opt)
    int bf_hookopts_validate(const bf_hookopts *hookopts, bf_hook hook)


cdef extern from "bpfilter/matcher.h":
    enum bf_matcher_type:
        BF_MATCHER_SET          # matches a key built from the packet against a set
        _BF_MATCHER_TYPE_MAX
    enum bf_matcher_op:
        BF_MATCHER_IN
        _BF_MATCHER_OP_MAX

    struct bf_matcher:
        pass

    const char *bf_matcher_type_to_str(bf_matcher_type type)
    const char *bf_matcher_op_to_str(bf_matcher_op op)
    int bf_matcher_type_from_str(const char *str, bf_matcher_type *type)
    int bf_matcher_op_from_str(const char *str, bf_matcher_op *op)
    # negation is a flag on any matcher, not a "not" operator
    int bf_matcher_new_from_raw(bf_matcher **matcher, bf_matcher_type type,
                                bf_matcher_op op, const char *payload, bint negate)
    void bf_matcher_free(bf_matcher **matcher)
    bf_matcher_type bf_matcher_get_type(const bf_matcher *matcher)
    bf_matcher_op bf_matcher_get_op(const bf_matcher *matcher)
    bint bf_matcher_get_negate(const bf_matcher *matcher)
    const void *bf_matcher_payload(const bf_matcher *matcher)

    # How libbpfilter parses and prints each (type, op)'s payload; print() writes to stdout.
    ctypedef void (*bf_matcher_print_fn)(const void *payload)
    struct bf_matcher_ops:
        size_t ref_payload_size
        bf_matcher_print_fn print_payload "print"
    const bf_matcher_ops *bf_matcher_get_ops(bf_matcher_type type, bf_matcher_op op)


cdef extern from "bpfilter/counter.h":
    struct bf_counter:
        uint64_t count
        uint64_t size


cdef extern from "bpfilter/rule.h":
    struct bf_rule:
        uint32_t index
        bf_list matchers
        uint8_t log
        uint64_t log_rate_ns         # 0: log every match
        uint64_t mark
        uint8_t has_counters
        bf_counter counters
        bint disabled                # set by libbpfilter for rules that can never match
        bf_verdict verdict
        uint32_t redirect_ifindex    # for BF_VERDICT_REDIRECT
        bf_redirect_dir redirect_dir

    bint bf_rule_mark_is_set(const bf_rule *rule)
    uint32_t bf_rule_mark_get(const bf_rule *rule)   # mark keeps an is-set flag in its high bits
    int bf_rule_new(bf_rule **rule)
    void bf_rule_free(bf_rule **rule)
    int bf_rule_pack(const bf_rule *rule, void *pack)


cdef extern from "bpfilter/core/hashset.h":
    struct bf_hashset_elem:
        void *data
        bf_hashset_elem *next

    ctypedef struct bf_hashset:     # insertion-ordered: a chain's named sets, a set's elements
        bf_hashset_elem *head


cdef extern from "bpfilter/set.h":
    struct bf_set:
        const char *name             # NULL: anonymous, owned by its matcher
        bf_matcher_type key[8]       # BF_SET_MAX_N_COMPS in the header; n_comps are used
        size_t n_comps
        bf_hashset elems             # each element: the components' payloads, back to back
        size_t min_size              # 0.8: room in the BPF map for elements added later

    int bf_set_new_from_raw(bf_set **set, const char *name, const char *raw_key,
                            const char *raw_payload)
    void bf_set_free(bf_set **set)


cdef extern from "bpfilter/matcher.h":
    # 0.8: chains own named sets, matchers own anonymous ones
    int bf_matcher_new_for_named_set(bf_matcher **matcher, const bf_set *set, bint negate)
    int bf_matcher_new_for_anon_set_from_raw(bf_matcher **matcher, const char *raw_key,
                                             const char *raw_payload, bint negate)


cdef extern from "bpfilter/chain.h":
    struct bf_chain:
        const char *name
        uint8_t flags
        bf_hook hook
        bf_verdict policy
        bf_hashset sets
        bf_list rules
        bf_counter policy_counters
        bf_counter error_counters

    int bf_chain_new(bf_chain **chain, const char *name, bf_hook hook,
                     bf_verdict policy, bf_hashset *sets, bf_list *rules)
    void bf_chain_free(bf_chain **chain)
    int bf_chain_add_set(bf_chain *chain, bf_set *set)
    int bf_chain_add_rule(bf_chain *chain, bf_rule *rule)
    const bf_set *bf_chain_get_set_by_name(const bf_chain *chain, const char *set_name)
    const bf_set *bf_chain_get_set_for_matcher(const bf_chain *chain, const bf_matcher *matcher)


cdef extern from "bpfilter/bpfilter.h":
    int bf_chain_set(bf_chain *chain, bf_hookopts *hookopts)
    int bf_chain_load(bf_chain *chain)
    int bf_chain_attach(const char *name, const bf_hookopts *hookopts)
    int bf_chain_get(const char *name, bf_chain **chain, bf_hookopts **hookopts)
    int bf_chain_flush(const char *name)
    int bf_chain_update(const bf_chain *chain)
    int bf_chain_update_set(const char *name, const bf_set *to_add, const bf_set *to_remove)
    int bf_ruleset_flush()
    int bf_ruleset_get(bf_list *chains, bf_list *hookopts)
