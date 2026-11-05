# Developing bpyfilter

bpyfilter needs bpfilter 0.8, which distributions don't ship yet, and root to
load BPF programs. `dev/vm` runs everything in a throwaway
[Lima](https://lima-vm.io) VM (Fedora 44) with bpfilter built from source, and
this checkout mounted at `/src/bpyfilter`:

```bash
dev/vm create              # create, boot, build bpfilter v0.8.0 (takes a while)
dev/vm test                # install this checkout in the VM and run the tests
dev/vm test -k sets -x     # arguments go to pytest
dev/vm shell               # a root shell in the VM
dev/vm bpfilter main       # rebuild bpfilter at another tag, branch or commit
dev/vm delete
```

- `VM=name` runs several VMs side by side (default: `bpyfilter-dev`), and
  `LIMACTL=path` points at `limactl` if it isn't on your `PATH`.
- `lima.yaml` defines the VM, and `provision.sh` builds bpfilter at first boot;
  `dev/vm bpfilter REF` runs it again to switch versions.
- `dev/vm test` installs this checkout in the VM, then runs `tests/` as root.
  The integration tests need root and bpfilter 0.8; without them they're
  skipped, and the rest still runs.

## Trying it interactively

IPython is installed in the VM, with a tab-completion menu that's readable on
light and dark terminals (`dev/ipython-completion-menu.py`, installed for root by
`provision.sh`). From a root shell (`dev/vm shell`), leave the checkout first, for
the same reason as the examples below:

```bash
cd /tmp && ipython
```

```python
>>> import bpyfilter
>>> bpyfilter.chains()
>>> fw = bpyfilter.Chain.load("fw")
```

## Running the examples

The examples need root and bpfilter 0.8, so they run in the VM too. The tests
run each one and check its output:

```bash
dev/vm test -k examples                 # every example
dev/vm test -k "examples and xdp"       # just some: -k matches the paths, examples/xdp/...
```

To see one example's output, run it in the VM:

```bash
dev/vm shell sh -c 'cd /tmp && python3 /src/bpyfilter/examples/xdp/drop_ping.py'
```

- Run them from outside the checkout (`cd /tmp`): from `/src/bpyfilter`, Python
  would import the source folder, where the Cython extension isn't built.
- They use the bpyfilter installed in the VM, which `dev/vm test` installs from
  this checkout: after changing bpyfilter itself, run `dev/vm test` (or
  `dev/vm test -k examples`) first.
- `examples/cgroup_skb/per_cgroup_firewall.py` isn't in the tests: it pings
  `1.1.1.1`, so it needs the network.

