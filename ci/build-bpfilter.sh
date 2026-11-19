#!/bin/bash
# Build libbpf and bpfilter from source and install them in /usr, for building
# bpyfilter's wheels: cibuildwheel runs it once per manylinux container (see
# [tool.cibuildwheel] in pyproject.toml), then auditwheel copies libbpfilter,
# libbpf and their dependencies into each wheel.
#
# These are the versions bundled in the published wheels. bpfilter's comes from
# bpyfilter's own version in pyproject.toml: 0.8.0.N bundles bpfilter v0.8.0.
set -euxo pipefail

cd "$(dirname "$0")/.."
VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' pyproject.toml)
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "pyproject.toml: version '$VERSION' isn't <bpfilter version>.<revision>" >&2
  exit 1
fi
BPFILTER_VERSION=v${VERSION%.*}
LIBBPF_VERSION=v1.8.0

# manylinux_2_34 is AlmaLinux 9: clang compiles bpfilter's BPF stubs, xxd embeds
# them, bison and flex build bfcli (part of bpfilter's build).
dnf install -y --setopt=install_weak_deps=False \
  clang bison flex vim-common elfutils-libelf-devel zlib-devel pkgconf-pkg-config

WORK=$(mktemp -d)
# GitHub's tag archives come from `git archive`, which fills in the version
# bpfilter's CMake reads when there's no .git.
curl -fsSL "https://github.com/libbpf/libbpf/archive/refs/tags/${LIBBPF_VERSION}.tar.gz" | tar -xz -C "$WORK"
curl -fsSL "https://github.com/meta/bpfilter/archive/refs/tags/${BPFILTER_VERSION}.tar.gz" | tar -xz -C "$WORK"

# libbpf, with its copy of the kernel's BPF UAPI headers (newer than the image's).
make -C "$WORK/libbpf-${LIBBPF_VERSION#v}/src" -j"$(nproc)" \
  PREFIX=/usr LIBDIR=/usr/lib64 install install_uapi_headers

BPFILTER_SRC="$WORK/bpfilter-${BPFILTER_VERSION#v}"
cmake -S "$BPFILTER_SRC" -B "$BPFILTER_SRC/build" \
  -DWITH_DOCS=OFF -DWITH_TESTS=OFF -DCMAKE_BUILD_TYPE=release -DCMAKE_INSTALL_PREFIX=/usr
cmake --build "$BPFILTER_SRC/build" -j"$(nproc)"
cmake --install "$BPFILTER_SRC/build"
ldconfig

rm -rf "$WORK"
