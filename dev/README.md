# Developing bpyfilter

bpyfilter needs bpfilter 0.8, which distributions don't ship yet, and root to
load BPF programs. `dev/vm` runs everything in a throwaway
[Lima](https://lima-vm.io) VM (Fedora 44), with this checkout mounted at
`/src/bpyfilter`, and tests bpyfilter the way users get it: as a wheel, built the
way CI builds the ones on PyPI, with its own libbpfilter.

```bash
dev/vm create              # create, boot, bake the build image (takes a while)
dev/vm test                # build this checkout's wheel, install it, run the tests
dev/vm test -k sets -x     # arguments go to pytest
dev/vm shell               # a root shell in the VM
dev/vm reprovision         # run the provisioning again (after bumping bpfilter, say)
dev/vm bpfilter main       # build bpfilter at another tag, branch or commit instead
dev/vm delete
```

- `VM=name` runs several VMs side by side (default: `bpyfilter-dev`), and
  `LIMACTL=path` points at `limactl` if it isn't on your `PATH`.
- `lima.yaml` defines the VM, and `provision.sh` provisions it at first boot:
  podman, uv, the tests' dependencies, and the build image.
- **The build image** (`build-image.sh`) is the manylinux image CI's cibuildwheel
  uses, with `ci/build-bpfilter.sh` already run in it: libbpf and bpfilter, built
  once instead of for every wheel. Its tag is a hash of the base image, the
  bpfilter version and `ci/build-bpfilter.sh`, so changing any of them (bumping
  `pyproject.toml`'s version to a new bpfilter, say) builds a new image on the
  next `dev/vm test`. `dev/vm reprovision` rebuilds it from scratch.
- **`dev/vm test`** (`test.sh`) runs cibuildwheel (CI's version, read from
  `release.yml`) in the VM with podman, in the build image, for the VM's Python;
  auditwheel bundles libbpfilter into the wheel, as on PyPI. It then installs the
  wheel (it's in `wheelhouse/dev/`) and runs `tests/` as root, on the VM's
  kernel. The integration tests need root and BPF; without them they're skipped,
  and the rest still runs.
- **`dev/vm bpfilter REF`** builds the image with bpfilter at `REF` (a tag,
  branch or commit) instead of the version `pyproject.toml` names, until the next
  `dev/vm reprovision`. The wheel's version doesn't change: it's for trying
  bpyfilter against other bpfilters, not for releasing.
- bpfilter isn't installed on the VM itself (so no `bfcli` there): bpyfilter
  only uses the wheel's libbpfilter. A VM made before wheel builds needs a
  `dev/vm reprovision`, which also removes the bpfilter it built in `/usr`.

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
- They use the bpyfilter installed in the VM, the wheel `dev/vm test` last built
  from this checkout: after changing bpyfilter itself, run `dev/vm test` (or
  `dev/vm test -k examples`) first.
- `examples/cgroup_skb/per_cgroup_firewall.py` isn't in the tests: it pings
  `1.1.1.1`, so it needs the network.

