#!/bin/bash
# Build this checkout's wheel the way CI does, install it, and run the tests as root.
#   bash dev/test.sh [PYTEST ARGS]     in the VM, as root: `dev/vm test` runs it
# cibuildwheel (CI's version) builds the wheel for the VM's Python, in the build image
# (dev/build-image.sh), and auditwheel bundles libbpfilter into it, as in the wheels
# on PyPI. The tests then run against that wheel, on the VM's kernel.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v podman >/dev/null || ! command -v uv >/dev/null; then
  echo "This VM was provisioned before wheel builds (no podman or uv): run dev/vm reprovision" >&2
  exit 1
fi

IMAGE=$(bash dev/build-image.sh)
ARCH=$(uname -m)
PY=$(python3 -c 'import sys; print("cp%d%d" % sys.version_info[:2])')
CIBW_VERSION=$(sed -n 's|.*uses: pypa/cibuildwheel@v\([0-9.]*\).*|\1|p' .github/workflows/release.yml)
OUT=wheelhouse/dev

rm -rf "$OUT"
# bpfilter is already in the image, so before-all has nothing to do; and the tests
# run below, as root on the VM's kernel, instead of in the container.
env CIBW_CONTAINER_ENGINE=podman \
    "CIBW_MANYLINUX_${ARCH^^}_IMAGE=$IMAGE" \
    CIBW_BEFORE_ALL=true \
    CIBW_BUILD="$PY-manylinux_$ARCH" \
    CIBW_TEST_SKIP='*' \
  uvx --quiet "cibuildwheel==$CIBW_VERSION" --platform linux --output-dir "$OUT"

WHEEL=$(ls "$OUT"/bpyfilter-*.whl)
python3 -m pip install -q --root-user-action=ignore --force-reinstall --no-deps "$WHEEL"
echo "--- testing $(basename "$WHEEL")"
# From outside the checkout, so `import bpyfilter` finds the wheel, not the source folder.
cd /tmp
python3 -m pytest -p no:cacheprovider -ra /src/bpyfilter/tests "$@"
