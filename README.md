# bpyfilter

Crazy idea... write firewalls in Python (technically, write [bpfilter](https://bpfilter.io) programs in Python, but bpfotato, bpftata).

bpyfilter is a binding for libbpfilter: you write packet filtering rules in Python, and bpfilter turns them into BPF programs and attaches them to the kernel.

In software development, as in screenwriting, it's better to show, not tell... so here is how it works: nobody can ping this machine.

```python
from bpyfilter import ACCEPT, DROP, NF_LOCAL_IN, Chain
from bpyfilter.match import icmp, ip4

chain = Chain("no_ping", NF_LOCAL_IN(priorities=(101, 102)), policy=ACCEPT)   # netfilter: the whole system
chain.rule(ip4.proto == "icmp", icmp.type == "echo-request", verdict=DROP)
chain.install()                          # into the kernel: nobody can ping us now

chain.counters()
# ChainCounters(hook='BF_HOOK_NF_LOCAL_IN', policy_verdict='ACCEPT', attached=True,
#               rules=[(2, 196)], policy=(0, 0), error=(0, 0))
chain.flush()                            # and we're pingable again
```

A chain, in bpfilter's terms, is a group of rules that decide the fate of a packet. The Python syntax looks very similar to bpfilter's own language; if you don't believe me, turn a chain into a string:

```python
print(str(chain))
```

```
chain no_ping BF_HOOK_NF_LOCAL_IN{priorities=101-102} ACCEPT
    rule
        ip4.proto eq icmp
        icmp.type eq echo-request
        counter
        DROP
```

## Hooks

Chains have hooks: a hook is where a chain is attached, and it decides what the chain sees. A hook is called with the options
that say where to attach (`XDP(ifindex="eth0")`), like bfcli's `BF_HOOK_XDP{ifindex=2}`.

For example, two other ways we could have written the `no_ping` chain would be to attach it to the proper interface, or to a group of processes:

```python
# only on eth0, at the driver, before the kernel does anything else with the packet
chain = Chain("no_ping", XDP(ifindex="eth0"), policy=ACCEPT)
chain.rule(ip4.proto == "icmp", icmp.type == "echo-request", verdict=DROP)

# only for the processes in one cgroup: they can't ping anyone
chain = Chain("no_ping", CGROUP_SKB_EGRESS(cgpath="/sys/fs/cgroup/myapp"), policy=ACCEPT)
chain.rule(ip4.proto == "icmp", icmp.type == "echo-request", verdict=DROP)
```

You don't need to pass the hook's options when you create the chain: you can pass them (or override them) at install time, for instance:

```python
chain = Chain("no_ping", XDP, policy=ACCEPT)
chain.rule(ip4.proto == "icmp", icmp.type == "echo-request", verdict=DROP)
chain.install(ifindex="eth0")
```

The full list of hooks, and the options each one takes, is in
[Current hooks](#current-hooks).

## Matchers

When writing rules, you can do it three ways... the following are all the same:

```python
from bpyfilter import Matcher, Op
from bpyfilter.match import ip4

chain.rule(ip4.daddr == "1.1.1.1", verdict=DROP)                  # Python expressions
chain.rule("ip4.daddr eq 1.1.1.1", verdict=DROP)                  # bfcli's text
chain.rule((Matcher.IP4_DADDR, Op.EQ, "1.1.1.1"), verdict=DROP)   # enums, for generated rules
```

| expression | bfcli |
|---|---|
| `ip4.daddr == ip_address("1.1.1.1")` | `ip4.daddr eq 1.1.1.1` |
| `ip4.dnet == ip_network("10.0.0.0/8")` | `ip4.dnet eq 10.0.0.0/8` |
| `tcp.dport != 22`, or `~(tcp.dport == 22)` | `tcp.dport not eq 22` |
| `tcp.dport.range(1024, 65535)` | `tcp.dport range 1024-65535` |
| `~tcp.dport.range(1, 1023)` | `tcp.dport not range 1-1023` |
| `tcp.flags.any("syn", "ack")` / `.all(...)` | `tcp.flags any syn,ack` |
| `icmp.type == "echo-request"` | `icmp.type eq echo-request` |
| `ip4.proto == socket.IPPROTO_ICMP` | `ip4.proto eq 1` (= `icmp`) |

Several matchers in one rule must all match: `chain.rule(ip4.proto == "icmp",
ip4.daddr == "8.8.8.8", verdict=...)`. Every field libbpfilter knows is
available as `family.name` (`meta.l4_proto`, `ip6.saddr`, `icmp.type`...);
payloads go through `str()` and are parsed by libbpfilter, so strings, numbers
and `ipaddress` objects all work.

A matcher is a rule's condition, not a truth value: Python turns `not`, `and`,
`or` and `if` into plain bools, so they can't build rules, and using one
raises `TypeError` (instead of silently meaning `True`). Negate with `~`.

`meta.pid == 1234` matches a process (its PID in the initial PID namespace),
only on the `CGROUP_SOCK_ADDR_*` hooks: they run in the process calling
`connect()` or `sendmsg()`, while the packet hooks only see packets. A PID only
names a process until it exits, then the kernel can give it to an unrelated
process, which the rule would match: keep such rules short-lived, remove the
PID when the process exits, or use a cgroup per process (cgroup IDs aren't
reused). Your own children are safe until you `wait()` for them: a zombie
keeps its PID.

## Sets

We have extensive support for sets, too much support really. A set matches a
packet against many values at once (a hash map, or a longest-prefix-match trie
for networks), instead of one rule per value, and you can change it while the
chain runs:

```python
chain = Chain("blocklist", NF_LOCAL_OUT(priorities=(101, 102)), policy=ACCEPT)
blocked = chain.add_set("blocked", ip4.daddr, ["8.8.4.4"], auto_update=True)
chain.rule(blocked, ip4.proto == "icmp", verdict=DROP)     # icmp, to anything in blocked
chain.install()
# can't ping 8.8.4.4, but can ping 8.8.8.8
blocked.add("8.8.8.8")       # auto_update=True pushes it right away (without it: blocked.update_chain())
# now we can't ping 8.8.8.8 either
```

There are two types of sets: one defined inline in a rule (they don't have names), and one defined on the chain, which can be referenced by name in multiple rules... we support both. Examples:

```python
from ipaddress import ip_address, ip_network
from bpyfilter import SetRef
from bpyfilter.match import ip4, key, tcp, udp

blocked = chain.add_set("blocked", ip4.daddr, [ip_address("1.1.1.1"), "8.8.8.8"])
svc = chain.add_set("svc", (ip4.daddr, tcp.dport), [("10.0.0.1", 443), ("10.0.0.2", 22)])
lan = chain.add_set("lan", ip4.dnet, [ip_network("10.0.0.0/8"), ip_network("192.168.0.0/16")])

chain.rule(blocked, verdict=DROP)                 # shortcut for: ip4.daddr in the blocked set
chain.rule(ip4.daddr.isin(blocked), verdict=DROP) # the same as before
chain.rule(~blocked, verdict=DROP)                # ip4.daddr *not* in the blocked set
chain.rule(svc, verdict=DROP)                     # block the pair ip4.daddr/tcp.dport
chain.rule(SetRef("svc"), verdict=DROP)           # the same as the one before, by name instead of by object
chain.rule(lan, udp.dport == 53, verdict=ACCEPT)  # accept DNS to the local networks (a trie)
chain.rule(ip4.saddr.isin(["10.0.0.1", "10.0.0.2"]), verdict=DROP)              # inline set, made on the fly
chain.rule(key(ip4.daddr, tcp.dport).isin([("1.1.1.1", 443)]), verdict=DROP)    # inline, composite
chain.rule("(ip4.daddr) in blocked", verdict=DROP)                              # bfcli's text
```

### Updating a set

A bpyfilter `Set` also acts as a Python set. You can mutate it, then `update_chain()` pushes just the
changes to the chain in bpfilter, without replacing the chain (bfcli's `chain
update-set`, libbpfilter's `bf_chain_update_set`):

```python
blocked = chain.add_set("blocked", ip4.daddr, ["8.8.8.8"])
live = chain.add_set("live", ip4.daddr, [], auto_update=True)
chain.rule(blocked, verdict=DROP).rule(live, verdict=DROP).install()

blocked.add("1.2.3.4")
blocked.discard(ip_address("8.8.8.8"))
blocked |= {"9.9.9.9", "10.0.0.1"}
blocked.update_chain()                      # one push, for all of the above

live.add("1.2.3.4")                         # auto_update: pushed right away
```

A set added to a chain that's already installed isn't in bpfilter yet: its
changes stay local (pushing them raises, saying so) until `chain.update()`
sends it.

A set keyed on one port field takes ranges, `Set(tcp.dport, [22, "8000-8080",
range(9000, 9010)])`: libbpfilter stores every port, and so does the Python
set, so `8042 in s` and `s.discard(8042)` work.

`in`, `len()`, iteration, `add`, `discard`, `remove`, `update`,
`difference_update`, `clear`, `|=` and `-=` all work; elements compare as the
text libbpfilter gets, so `"8.8.8.8"` and `ip_address("8.8.8.8")` are the same.
`update_chain()` pushes to the set's chain; on a set that belongs to no chain it
raises, and before the chain is installed changes are only local (`install()`
sends everything). A set is not a truth value: use `len(s)`.

## Mutating a chain

| | what changes | attachment | counters |
|---|---|---|---|
| `chain.install()` | everything: creates or replaces the chain | attaches it with the hook's options, or `install(**hookopts)` (none: loaded only) | restart |
| `chain.update()` | its rules and sets, in place | kept, whatever it is | restart |
| `s.update_chain()`, `chain.update_set(...)` | one set's elements, in place | kept | kept |

Rules are immutable (`Rule` is a frozen dataclass): to change them, replace
them in `chain.rules` and `update()` the chain:

```python
chain.rules[0] = Rule([ip4.daddr == "1.1.1.2"], verdict=DROP)    # or chain.rules.clear(); chain.rule(...)
chain.update()
```

## Chain lifecycle (starting and stopping a chain)

You can enable and disable (install and flush) a chain in multiple ways. The first is to explicitly call `install()` and `flush()`:

```python
chain = (Chain("no_ping", NF_LOCAL_IN(priorities=(101, 102)), policy=ACCEPT)
         .rule(ip4.proto == "icmp", icmp.type == "echo-request", verdict=DROP)
         .install())                     # into the kernel: nobody can ping us now

chain.flush()                            # and we're pingable again
```

With `install()` your chain becomes active, and with `flush()` the chain disappears... in true Python fashion, you can also use a context manager: entering the block installs the chain, and leaving it removes it:

```python
with (Chain("no_ping", NF_LOCAL_IN(priorities=(101, 102)), policy=ACCEPT)
      .rule(ip4.proto == "icmp", icmp.type == "echo-request", verdict=DROP)) as chain:
    ...                                  # things happen: nobody can ping us

# the chain is gone from the kernel, even if the block raised
```

Rules added inside the block are local until `chain.update()` sends them.

In particular, the chain constructor is very useful: you can create sets and rules at once.

```python
fw = Chain(
    "fw",
    CGROUP_SKB_EGRESS(cgpath="/sys/fs/cgroup/myapp"),
    policy=ACCEPT,
    sets={"foo": Set(ip4.daddr, ["1.1.1.1"])},
    rules=[
        Rule([SetRef("foo")], verdict=DROP),
        Rule([~SetRef("foo"), tcp.dport == 22], verdict=DROP),
    ],
)
```

## Loading a chain

You can also use bpyfilter to debug existing chains (or modify them): `Chain.load(name)` reads a chain back from bpfilter, whoever made it (bpyfilter,
bfcli, another program), as an installed `Chain`: its sets, rules, policy and,
if it's attached, its hook options.

```python
fw = Chain.load("no_ping")
print(fw)                                          # the chain, as bfcli's text
fw.sets["blocked"].add("9.9.9.9")
fw.sets["blocked"].update_chain()                  # change a set in place
fw.rules.append(Rule([tcp.dport == 23], verdict=DROP))
fw.update()                                        # or its rules
```

Payloads and set elements come back the way libbpfilter prints them (`"443"`,
`"10.0.0.0/8"`, `"icmp"`), and comparing works as usual (`443 in s`). Rules with
a mark or a log rate limit (`log every 1s`) raise `ValueError`: bpyfilter can't
express those yet.

## Starting libbpfilter: `setup()`

bpfilter has no daemon: libbpfilter runs inside your process, and starts on
the first chain operation. To start it with options, or for one block only:

```python
with bpyfilter.setup(bpffs_path="/sys/fs/bpf"):           # libbpfilter for the block
    with Chain("fw", CGROUP_SKB_EGRESS(cgpath=cg), sets={"blocked": Set(ip4.daddr, ["1.1.1.1"])},
               rules=[Rule([SetRef("blocked")], verdict=DROP)]) as fw:
        fw.sets["blocked"].add("8.8.8.8"); fw.sets["blocked"].update_chain()
    # here the chain is gone from bpfilter, even if the block raised
```

`setup()` returns a context manager that tears libbpfilter down at the end of
the block (chains installed outside a `with Chain` stay attached). As in
"Chain lifecycle", `with chain:` installs the chain and removes it when the
block ends; a chain that's already installed stays as it is, so
`with chain.install(ifindex=2):` works too, for options given to `install()`.

## Examples

There are plenty of examples in this repo... this is mostly a teaching tool, and the best way to learn is with examples.

They're organized in one folder per hook. All need root, and run offline: they use loopback
addresses, a scratch cgroup, or a throwaway network namespace (`bpyf-lab`,
a veth cable to this host's `bpyf0`), and remove what they create.

| | |
|---|---|
| **`examples/xdp/`** | |
| `drop_ping.py` | drop pings at the driver of one interface, TCP still gets through |
| `blocklist.py` | a set of banned source addresses, grown in place while attached |
| **`examples/tc/`** | |
| `ingress_ports.py` | close TCP ports on an interface, with an inline set of ports |
| `egress_ping.py` | one-way ping: drop outgoing echo requests, not the replies |
| **`examples/netfilter/`** | |
| `no_ping.py` | nobody pings this machine (`NF_LOCAL_IN`, `priorities=`) |
| `local_out.py [addr ...]` | a blocklist for every process on the machine (`NF_LOCAL_OUT`) |
| **`examples/cgroup_skb/`** | |
| `per_cgroup_firewall.py [cmd]` | no ping, no DNS, for one command |
| `blocklist.py [addr ...]` | a named set of destinations a command can't reach |
| `allowlist.py` | policy DROP, plus a trie of networks it may reach |
| `not_in_set.py` | "anything except the set", with `~blocked` |
| `traffic_meter.py [cmd]` | `CONTINUE` rules as counters: a command's packets per protocol |
| `declarative.py` | a whole chain in one expression: `sets=`, `rules=`, `SetRef`, `with` blocks |
| `update_set.py` | change a running blocklist: set methods, `update_chain()`, `auto_update` |
| `tcp_ports.py` | a port range and an (address, port) set, against local listeners |
| **`examples/cgroup_sock_addr/`** | |
| `connect4.py` | the same rule on `CGROUP_SKB_EGRESS` (connect times out) and `CONNECT4` (fails at once with `EPERM`) |
| `sendmsg4.py` | refuse UDP `sendto()` to some ports |
| `per_pid.py` | two processes in one cgroup, only one can connect: `meta.pid` |

`examples/_lab.py` has the helpers they share. To run them (in the dev VM, or as root on a
machine with bpfilter 0.8), see [dev/README.md](dev/README.md#running-the-examples).

## Installing and using it

bpyfilter needs **bpfilter 0.8**, which has no daemon: libbpfilter generates and
loads the BPF programs itself, from your process. Distributions still ship 0.6
(Fedora 44 and 45, as of November 2026), so build it from source:

```bash
sudo dnf install clang cmake gcc libbpf-devel bison flex sed xxd git
git clone --branch v0.8.0 https://github.com/meta/bpfilter.git && cd bpfilter
cmake -S . -B build -DWITH_DOCS=OFF -DWITH_TESTS=OFF -DCMAKE_INSTALL_PREFIX=/usr
cmake --build build -j && sudo cmake --install build
pip install .                                 # in bpyfilter: builds the Cython extension
```

## API

| | |
|---|---|
| `Hook`, `Verdict`, `Matcher`, `Op` | `StrEnum`s read from the installed libbpfilter (`Hook.CGROUP_SKB_EGRESS`, `Verdict.DROP`, `Matcher.IP4_DADDR`, `Op.RANGE`...). Plain strings (`"BF_HOOK_XDP"` or `"XDP"`) work too |
| `ACCEPT`, `DROP`, `CONTINUE`, `XDP`, `CGROUP_SKB_EGRESS`, ... | every verdict and hook, also importable on its own: `from bpyfilter import CGROUP_SKB_EGRESS, DROP` |
| `NF_LOCAL_IN(priorities=(101, 102))`, `XDP(ifindex="eth0")`, ... | a hook called with its options: a `HookSpec`, which `Chain` takes in place of the hook; checked by libbpfilter right away; `str()` is bfcli's `BF_HOOK_NF_LOCAL_IN{priorities=101-102}` |
| `bpyfilter.match` | one namespace per field family (`ip4.daddr`...), and `key(*fields)` for composite inline sets |
| `bpyfilter.setup(bpffs_path="/sys/fs/bpf", with_bpf_token=False, verbose=0)` | start libbpfilter in this process, with options; also a context manager (`with bpyfilter.setup():`). Optional: the first chain operation starts it with the defaults; importing never does |
| `bpyfilter.teardown()`, `bpyfilter.is_setup()` | stop it (also runs at exit; chains stay attached), and ask |
| `Chain(name, hook, policy=ACCEPT, sets=None, rules=None)` | a chain for one hook, bare (`NF_LOCAL_IN`) or with its options (`NF_LOCAL_IN(priorities=(101, 102))`); `sets={name: Set}` declares sets, `rules=[Rule, ...]` starts its rules; `with chain:` installs it for the block and removes it at the end |
| `chain.rule(*matchers, verdict=..., counters=True, log=False, redirect=None)` | append a rule; `verdict` is required; `log=True` logs everything the hook can (`bfcli chain logs`), or some layers: `"link"`, `"internet"`, `"transport"` (a tuple for several), `"5-tuple"`; `redirect=(interface, "in" or "out")` with `REDIRECT` (returns the chain) |
| `Set(key, elements=(), name=None, auto_update=False, min_size=0)` | a set: a matcher for rules, and a Python set; owned by at most one chain (`s.chain`), and needs a name (letters, digits, `_`, `-`) to join one; `min_size` reserves room for elements added later; `s.bind(chain, name=None)` / `s.unbind()` |
| `SetRef(name)` | a reference to a set the chain declares, resolved at `install()`/`update()`; `~SetRef(name)` negates it |
| `chain.sets` | the chain's sets: `[name]` / `[index]`, `[name] = Set`, `del [name]`, `in`, `len`, iteration, `.names()` |
| `chain.add_set(name, key, elements=(), auto_update=False, min_size=0)` | declare a named set on the chain; returns the `Set` (same as `chain.sets[name] = Set(key, elements)`) |
| `chain.install(**hookopts)` | create/replace it in bpfilter and attach, with the hook's options, or with `hookopts` (`ifindex=` for XDP/TC, `priorities=(a, b)` for netfilter, `cgpath=` for cgroups), which win; no options anywhere = load only (see [Current hooks](#current-hooks)) |
| `chain.rules` | the chain's rules: a list of frozen `Rule(matchers, verdict, ...)`; replace items, then `update()` |
| `s.update_chain()` | push the set's changes since the last push to its chain, in place; `auto_update=True` does it on every mutation |
| `chain.update()` | replace the rules and sets of an existing chain, keeping whatever it's attached to (bfcli's `chain update`); counters restart from zero |
| `chain.update_set(set, add=[...], remove=[...])` | add/remove elements of a named set in place: libbpfilter regenerates the program, no `install()` needed |
| `Chain.load(name)` | a chain bpfilter has, whoever made it, back as an installed `Chain` |
| `copy.copy(chain)`, `copy.copy(s)` | a chain with its own rules and sets, not installed (`install()` replaces the chain of that name); a set: unowned, same name and elements |
| `str(chain)`, `chain.to_bfcli(**hookopts)` | the chain as bfcli's text (with the last `install()`'s hook options, or these) |
| `chain.counters()` / `bpyfilter.get(name)` | `(packets, bytes)` per rule, plus policy and error counters |
| `chain.flush()` / `bpyfilter.flush(name)` / `bpyfilter.flush_all()` | detach and delete (not "empty the rules": the chain is gone) |

Errors from libbpfilter raise `BpfilterError` (an `OSError`); invalid hooks,
verdicts, matchers, payloads or set references raise `ValueError` before
anything reaches libbpfilter.

## How it works

| module | |
|---|---|
| `bpyfilter.chain` | `Chain`, `Rule`, `ChainCounters`, `get` / `flush` / `flush_all` |
| `bpyfilter.match` | the fields (`ip4.daddr`...), `Match`, and `parse()` for the three spellings |
| `bpyfilter.sets` | `Set`, `SetRef`, `ChainSets` (`chain.sets`), `Key` / `key()`, `SetMatch` |
| `bpyfilter.enums` | `Hook`, `Verdict`, `Matcher`, `Op`, read from libbpfilter; `HookSpec` |
| `bpyfilter._core` | the Cython layer: libbpfilter objects, memory, and calls |

Everything public is re-exported from `bpyfilter`.

`bpyfilter/_libbpfilter.pxd` declares the subset of libbpfilter's public API we
use, compiled against bpfilter-devel's headers; `_core.pyx` owns all the C
memory (`bf_chain_add_set` and `bf_chain_add_rule` take what they're given,
`bf_chain_get` returns objects the caller frees). libbpfilter's process-wide
context (`bf_ctx_setup`) is set up on first use and torn down at exit, so
importing bpyfilter needs no privileges. Matchers and sets are built from text
with `bf_matcher_new_from_raw()` and `bf_set_new_from_raw()`, so payloads are
parsed by libbpfilter itself. The chain owns its named sets, and a rule's
matcher points at one (`bf_matcher_new_for_named_set`); an inline set belongs
to its matcher (`bf_matcher_new_for_anon_set_from_raw`).
The enums are filled at import time from libbpfilter's `*_to_str()` functions.

## Development

See [dev/README.md](dev/README.md): a throwaway Lima VM with bpfilter built
from source, to develop and run the tests in.

## Compatibility

bpyfilter supports **bpfilter 0.8** only.

## Current hooks

Here is the list of current hooks, and the options each one takes:

| hook | sees | options |
|---|---|---|
| `XDP` | packets arriving on one interface, at the driver, before the kernel spends anything on them | `XDP(ifindex=...)` |
| `TC_INGRESS`, `TC_EGRESS` | packets in or out of one interface | `TC_INGRESS(ifindex=...)` |
| `NF_PRE_ROUTING`, `NF_LOCAL_IN`, `NF_FORWARD`, `NF_LOCAL_OUT`, `NF_POST_ROUTING` | every packet the kernel routes, IPv4 and IPv6, on every interface | `NF_LOCAL_IN(priorities=(a, b))` |
| `CGROUP_SKB_INGRESS`, `CGROUP_SKB_EGRESS` | packets of one cgroup's sockets | `CGROUP_SKB_EGRESS(cgpath=...)` |
| `CGROUP_SOCK_ADDR_CONNECT4` / `6`, `CGROUP_SOCK_ADDR_SENDMSG4` / `6` | `connect()` and UDP `sendmsg()` calls of one cgroup, before any packet exists: `DROP` fails the call with `EPERM` | `CGROUP_SOCK_ADDR_CONNECT4(cgpath=...)` |

- `ifindex=` takes an index or an interface name: bpyfilter looks names up
  (libbpfilter only reads numbers, and would read `"eth0"` as 0).
- `priorities=` is two different, non-zero priorities among the other netfilter
  users (nftables, iptables); bpfilter needs two to replace the chain
  atomically. `(101, 102)` or bfcli's `"101-102"`. Each update attaches the
  new program at the unused priority, so two netfilter chains on the same hook
  need different priorities, or their updates fail with `EBUSY`.
- `cgpath=` is a cgroup v2 directory, a string or a `Path`.
- The options are checked where you write them (an option the hook doesn't
  take, a bad value), by libbpfilter itself; interface names are looked up at
  `install()`, so the interface can come later.
- Nothing reaches the kernel until `install()`. With no options anywhere,
  `install()` loads the chain without attaching it.

A cgroup hook filters the packets **that cgroup's processes send**. If a
program asks another service to do the work, that service's packets are not
in the cgroup: with systemd-resolved, `getent hosts example.com` inside the
cgroup still resolves (resolved, in its own cgroup, sends the UDP 53 query),
while a direct query to `1.1.1.1:53` from inside is dropped. And a socket keeps
the cgroup it was created in: move a process into the cgroup *before* it opens
its sockets (or start it there, as the examples do).

## License

GPL-2.0-only, like libbpfilter, which bpyfilter links against. See `LICENSE`.
