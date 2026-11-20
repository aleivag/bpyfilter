#!/bin/bash
# Provision the dev VM: the tools to build bpyfilter's wheels the way CI does (podman,
# uv), the tests' dependencies, and the build image with bpfilter in it.
#   bash dev/provision.sh [REF]   REF: build bpfilter at this tag, branch or commit, instead
#                                 of the one pyproject.toml's version names (until the next
#                                 run without REF)
# Lima runs it at first boot; `dev/vm reprovision` and `dev/vm bpfilter REF` run it again.
set -euxo pipefail
cd "$(dirname "$0")/.."

# A readable tab-completion menu for IPython (sudo ipython uses root's profile).
install -D -m 644 dev/ipython-completion-menu.py \
  /root/.ipython/profile_default/startup/00-completion-menu.py

dnf install -y --setopt=install_weak_deps=False \
  podman uv python3-pip python3-pytest python3-ipython iputils

# bpyfilter comes from its wheel, with its own libbpfilter: no bpfilter on the VM itself,
# where another version's state could clash with the wheel's in bpffs. Fedora's package,
# and the one older versions of this script built from source in /usr.
dnf remove -y bpfilter bpfilter-devel || true
if [ -f /opt/bpfilter-src/build/install_manifest.txt ]; then
  xargs -r rm -f < /opt/bpfilter-src/build/install_manifest.txt
  rm -rf /opt/bpfilter-src
  ldconfig
fi

STATE=/var/lib/bpyfilter-dev
mkdir -p "$STATE"
rm -f "$STATE/bpfilter-ref"
[ -z "${1:-}" ] || echo "$1" > "$STATE/bpfilter-ref"

bash dev/build-image.sh
