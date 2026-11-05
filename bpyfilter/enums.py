"""Hook, Verdict, Matcher and Op: StrEnums read from the installed libbpfilter.

    Hook.CGROUP_SKB_EGRESS == "BF_HOOK_CGROUP_SKB_EGRESS"
    Hook.NF_LOCAL_IN(priorities=(101, 102))      # a HookSpec: the hook, and where to attach
    Verdict.DROP == "DROP"
    Matcher.IP4_DADDR == "ip4.daddr"
    Op.RANGE == "range"

Being StrEnums, plain strings work wherever a member does. Built at import time
from libbpfilter's *_to_str() functions (names only: no kernel, no bpffs), so
they always match the library bpyfilter was built against.
"""

import socket
from dataclasses import dataclass
from enum import StrEnum

from bpyfilter._core import check_hookopts, hook_names, matcher_op_names, matcher_type_names, verdict_names


class _Hook(StrEnum):
    def __call__(self, **options):
        """This hook, with the options to attach to it: a HookSpec, which Chain() takes in
        place of the hook (install() then attaches with them).

            NF_LOCAL_IN(priorities=(101, 102))      # netfilter: two different, non-zero
            XDP(ifindex="eth0"), TC_INGRESS(ifindex=2)
            CGROUP_SKB_EGRESS(cgpath="/sys/fs/cgroup/myapp")

        Options are checked here by libbpfilter (names, values, which hook takes which),
        except interface names, looked up at install(). No options: same as the bare hook."""
        return HookSpec(self, tuple(options.items()))


Hook = _Hook("Hook", {name.removeprefix("BF_HOOK_"): name for name in hook_names()})
Verdict = StrEnum("Verdict", {name: name for name in verdict_names()})
Matcher = StrEnum("Matcher", {name.replace(".", "_").upper(): name
                              for name in matcher_type_names() if not name.startswith("<")})
Op = StrEnum("Op", {name.upper(): name for name in matcher_op_names()})


@dataclass(frozen=True, slots=True)
class HookSpec:
    """A hook and its options, what NF_LOCAL_IN(priorities=(101, 102)) returns: bfcli's
    BF_HOOK_NF_LOCAL_IN{priorities=101-102}, which str() gives back. Nothing is attached
    until a chain using it is installed."""

    hook: Hook
    options: tuple = ()                         # ((name, value), ...)

    def __post_init__(self):
        object.__setattr__(self, "hook", member(Hook, self.hook))
        options = tuple((name, tuple(value) if isinstance(value, list) else value)
                        for name, value in self.options)
        object.__setattr__(self, "options", options)
        if options:
            check_hookopts(str(self.hook), _hookopts(dict(options), resolve_names=False))

    def __str__(self):
        opts = ",".join(f"{name}={value}" for name, value in _hookopts(dict(self.options)).items())
        return f"{self.hook}{{{opts}}}" if opts else str(self.hook)

    def __repr__(self):
        return f"{self.hook.name}({', '.join(f'{name}={value!r}' for name, value in self.options)})"


def _hookopts(opts, resolve_names=True):
    """bpyfilter's conveniences on top of libbpfilter's hook options: an interface name for
    ifindex= (looked up; libbpfilter would read "eth0" as 0), a (low, high) pair for
    priorities=, a Path for cgpath=. resolve_names=False leaves names out (checks only)."""
    opts = dict(opts)
    ifindex = opts.get("ifindex")
    if isinstance(ifindex, str) and not ifindex.isdigit():
        opts["ifindex"] = socket.if_nametoindex(ifindex) if resolve_names else 1
    priorities = opts.get("priorities")
    if isinstance(priorities, (tuple, list)):
        opts["priorities"] = "-".join(str(int(p)) for p in priorities)
    if "cgpath" in opts:
        opts["cgpath"] = str(opts["cgpath"])
    return opts


def member(enum, value):
    """The member of `enum` for a member, its value ("BF_HOOK_XDP") or its name ("XDP")."""
    try:
        return enum(value)
    except ValueError:
        if str(value) in enum.__members__:
            return enum.__members__[str(value)]
        raise ValueError(f"unknown {enum.__name__} {value!r}, one of: "
                         + ", ".join(enum.__members__)) from None


def matcher_type(field):
    """Matcher from a field (ip4.daddr), a Matcher, its value ("ip4.daddr") or its name."""
    if isinstance(getattr(field, "type", None), Matcher):         # a bpyfilter.match field
        return field.type
    try:
        return Matcher(field)
    except ValueError:
        try:
            return Matcher[str(field).replace(".", "_").upper()]
        except KeyError:
            raise ValueError(f"unknown matcher {field!r}") from None


__all__ = ["Hook", "HookSpec", "Matcher", "Op", "Verdict", "matcher_type", "member"]
