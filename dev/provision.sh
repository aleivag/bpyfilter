#!/bin/bash
# Provision the dev VM: build bpfilter from source and install it in /usr.
#   bash dev/provision.sh [REF]      REF: a tag, branch or commit; defaults to v0.8.0
# Lima runs it at first boot; `dev/vm bpfilter REF` runs it again to switch versions.
set -euxo pipefail

REF="${1:-v0.8.0}"
STAMP=/var/lib/bpyfilter-dev/bpfilter-ref
# A readable tab-completion menu for IPython (sudo ipython uses root's profile); on every run.
install -D -m 644 "$(dirname "$0")/ipython-completion-menu.py" \
  /root/.ipython/profile_default/startup/00-completion-menu.py

if [ -z "${FORCE:-}" ] && [ "$(cat "$STAMP" 2>/dev/null)" = "$REF" ]; then
  echo "bpfilter $REF is already installed (FORCE=1 to rebuild)"
  exit 0
fi

# bpfilter's documented build dependencies, plus what bpyfilter's build and tests need
# (and IPython, for trying bpyfilter interactively).
dnf install -y --setopt=install_weak_deps=False \
  clang cmake gcc make libbpf-devel bison flex sed xxd git \
  python3-devel python3-pip python3-pytest python3-ipython iputils
# Fedora's packaged bpfilter would shadow the one we build.
dnf remove -y bpfilter bpfilter-devel || true

SRC=/opt/bpfilter-src
rm -rf "$SRC"
git clone --quiet https://github.com/meta/bpfilter.git "$SRC"
git -C "$SRC" checkout --quiet "$REF"
cmake -S "$SRC" -B "$SRC/build" -DWITH_DOCS=OFF -DWITH_TESTS=OFF -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr
cmake --build "$SRC/build" -j"$(nproc)"
cmake --install "$SRC/build"
ldconfig

mkdir -p "$(dirname "$STAMP")"
echo "$REF" > "$STAMP"
echo "--- bpfilter $REF installed: $(git -C "$SRC" describe --tags --always)"
bfcli --version || true
