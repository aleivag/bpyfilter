#!/bin/bash
# Build libbpf and bpfilter from source and install them in /usr, for building
# bpyfilter's wheels: cibuildwheel runs it once per manylinux container (see
# [tool.cibuildwheel] in pyproject.toml), then auditwheel copies libbpfilter,
# libbpf and their dependencies into each wheel.
# dev/build-image.sh runs it too, to bake the dev VM's build image.
#
# These are the versions bundled in the published wheels. bpfilter's comes from
# bpyfilter's own version in pyproject.toml: 0.8.0.N bundles bpfilter v0.8.0.
# BPFILTER_REF (a tag, branch or commit) overrides it, for the dev VM only.
set -euxo pipefail

if [ -z "${BPFILTER_REF:-}" ]; then
  VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$(dirname "$0")/../pyproject.toml")
  if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "pyproject.toml: version '$VERSION' isn't <bpfilter version>.<revision>" >&2
    exit 1
  fi
  BPFILTER_REF=v${VERSION%.*}
fi
LIBBPF_VERSION=v1.8.0

# manylinux_2_34 is AlmaLinux 9: clang compiles bpfilter's BPF stubs, xxd embeds
# them, bison and flex build bfcli (part of bpfilter's build).
dnf install -y --setopt=install_weak_deps=False \
  clang bison flex vim-common elfutils-libelf-devel zlib-devel pkgconf-pkg-config

WORK=$(mktemp -d)
LIBBPF_SRC="$WORK/libbpf"
BPFILTER_SRC="$WORK/bpfilter"
mkdir "$LIBBPF_SRC" "$BPFILTER_SRC"
# GitHub's archives come from `git archive`, which fills in the version
# bpfilter's CMake reads when there's no .git.
curl -fsSL "https://github.com/libbpf/libbpf/archive/${LIBBPF_VERSION}.tar.gz" \
  | tar -xz -C "$LIBBPF_SRC" --strip-components=1
curl -fsSL "https://github.com/meta/bpfilter/archive/${BPFILTER_REF}.tar.gz" \
  | tar -xz -C "$BPFILTER_SRC" --strip-components=1

# libbpf, with its copy of the kernel's BPF UAPI headers (newer than the image's).
make -C "$LIBBPF_SRC/src" -j"$(nproc)" \
  PREFIX=/usr LIBDIR=/usr/lib64 install install_uapi_headers

cmake -S "$BPFILTER_SRC" -B "$BPFILTER_SRC/build" \
  -DWITH_DOCS=OFF -DWITH_TESTS=OFF -DCMAKE_BUILD_TYPE=release -DCMAKE_INSTALL_PREFIX=/usr
cmake --build "$BPFILTER_SRC/build" -j"$(nproc)"
cmake --install "$BPFILTER_SRC/build"
ldconfig

rm -rf "$WORK"
