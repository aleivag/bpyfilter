"""Shared by the examples: a scratch cgroup, a throwaway network, and small probes.

Every example adds this folder to sys.path (they live one level down, one folder
per hook) and imports from here. Everything is created for the example and
removed afterwards, so the examples are safe to run on a real machine.
"""

import contextlib
import os
import socket
import subprocess
from pathlib import Path

# --- cgroups (CGROUP_SKB_*, CGROUP_SOCK_ADDR_*) -------------------------------------------


@contextlib.contextmanager
def scratch_cgroup(name):
    """/sys/fs/cgroup/<name>, removed afterwards (killing anything left inside)."""
    cg = Path("/sys/fs/cgroup") / name
    cg.mkdir(exist_ok=True)
    try:
        yield cg
    finally:
        if (cg / "cgroup.procs").read_text().strip():
            (cg / "cgroup.kill").write_text("1")
        cg.rmdir()


def run_in(cg, cmd, **kwargs):
    """subprocess.run(cmd) with the child in cgroup `cg` before it starts: its sockets are
    created inside, so the cgroup's firewall sees them (a socket keeps its first cgroup)."""
    join = (lambda: (cg / "cgroup.procs").write_text(str(os.getpid()))) if cg else None
    return subprocess.run(cmd, capture_output=True, text=True, preexec_fn=join, **kwargs)


# --- a throwaway network (XDP, TC_*, NF_*) -------------------------------------------------


class Lab:
    """Two ends of a cable: this host (interface `bpyf0`, 10.250.0.1) and a network
    namespace (`bpyf-lab`, interface `bpyf1`, 10.250.0.2 and 10.250.0.3). Traffic between
    them crosses the host's `bpyf0` (XDP, TC) and its netfilter hooks; nothing else is touched."""

    ns, host_if, host_ip, ns_ips = "bpyf-lab", "bpyf0", "10.250.0.1", ("10.250.0.2", "10.250.0.3")

    @property
    def ns_ip(self):
        return self.ns_ips[0]

    def in_ns(self, cmd, **kwargs):
        """subprocess.run(cmd) inside the namespace."""
        return subprocess.run(["ip", "netns", "exec", self.ns, *cmd], capture_output=True, text=True, **kwargs)

    def ping_host(self, source=None):
        """True if the namespace (from address `source`, if given) can ping this host."""
        return self.in_ns(["ping", "-c1", "-W1", *(["-I", source] if source else []), self.host_ip]).returncode == 0

    def ping_ns(self):
        """True if this host can ping the namespace."""
        return ping(self.ns_ip)

    def connects_to_host(self, port):
        """True if the namespace can open a TCP connection to this host's `port` within a second."""
        probe = f"import socket; socket.create_connection(({self.host_ip!r}, {port}), timeout=1).close()"
        return self.in_ns(["python3", "-c", probe]).returncode == 0


@contextlib.contextmanager
def lab():
    """A Lab for the duration of the block; the namespace (and the cable) go away after."""
    def ip(*args, check=True):
        return subprocess.run(["ip", *args], capture_output=True, text=True, check=check)

    ip("netns", "del", Lab.ns, check=False)                     # leftovers from an aborted run
    ip("link", "del", Lab.host_if, check=False)
    ip("netns", "add", Lab.ns)
    try:
        ip("link", "add", Lab.host_if, "type", "veth", "peer", "name", "bpyf1")
        ip("link", "set", "bpyf1", "netns", Lab.ns)
        ip("addr", "add", f"{Lab.host_ip}/24", "dev", Lab.host_if)
        ip("link", "set", Lab.host_if, "up")
        for address in Lab.ns_ips:
            ip("netns", "exec", Lab.ns, "ip", "addr", "add", f"{address}/24", "dev", "bpyf1")
        ip("netns", "exec", Lab.ns, "ip", "link", "set", "bpyf1", "up")
        ip("netns", "exec", Lab.ns, "ip", "link", "set", "lo", "up")
        yield Lab()
    finally:
        ip("netns", "del", Lab.ns, check=False)                 # takes the veth pair with it
        ip("link", "del", Lab.host_if, check=False)


# --- probes ------------------------------------------------------------------------------


def ping(address, cg=None):
    """True if one ping to `address` gets an answer (from inside cgroup `cg`, if given)."""
    return run_in(cg, ["ping", "-c1", "-W1", str(address)]).returncode == 0


def tcp_connects(address, port, cg=None):
    """True if a TCP connection to address:port succeeds within a second."""
    probe = f"import socket; socket.create_connection(({str(address)!r}, {port}), timeout=1).close()"
    return run_in(cg, ["python3", "-c", probe]).returncode == 0


@contextlib.contextmanager
def listening(address, *ports):
    """TCP sockets listening on address:port for each port (the kernel finishes the
    handshake on its own, so connecting is enough to tell whether packets get through)."""
    sockets = [socket.create_server((str(address), port)) for port in ports]
    try:
        yield sockets
    finally:
        for s in sockets:
            s.close()


def show(ok):
    return "ok" if ok else "BLOCKED"
