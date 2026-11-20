#!/bin/bash
# Build, if it doesn't exist yet, the image the dev VM builds wheels in: the manylinux
# image CI's cibuildwheel uses, with ci/build-bpfilter.sh already run in it. The same
# build as CI's, without rebuilding bpfilter for every wheel. Prints the image's name.
#   bash dev/build-image.sh       in the VM, as root; FORCE=1 rebuilds the image
# The bpfilter it builds is the one pyproject.toml's version names, or the ref saved
# by `dev/vm bpfilter REF`. The image's tag is a hash of the base image, that ref and
# ci/build-bpfilter.sh: change any of them and the next run builds a new image.
set -euo pipefail
cd "$(dirname "$0")/.."

ARCH=$(uname -m)
# Same cibuildwheel as CI, and the manylinux image it pins for pyproject.toml's
# manylinux-<arch>-image (a digest, not a moving tag).
CIBW_VERSION=$(sed -n 's|.*uses: pypa/cibuildwheel@v\([0-9.]*\).*|\1|p' .github/workflows/release.yml)
BASE=$(uv run --quiet --no-project --with "cibuildwheel==$CIBW_VERSION" python - "$ARCH" <<'EOF'
import configparser, importlib.resources, sys, tomllib

arch = sys.argv[1]
with open("pyproject.toml", "rb") as f:
    image = tomllib.load(f)["tool"]["cibuildwheel"]["linux"][f"manylinux-{arch}-image"]
pins = configparser.ConfigParser(inline_comment_prefixes=("#",))
pins.read_string((importlib.resources.files("cibuildwheel") / "resources/pinned_docker_images.cfg").read_text())
print(pins[arch][image])
EOF
)

REF=$(cat /var/lib/bpyfilter-dev/bpfilter-ref 2>/dev/null || true)
if [ -z "$REF" ]; then
  VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' pyproject.toml)
  REF=v${VERSION%.*}
fi
HASH=$({ echo "$BASE $REF"; cat ci/build-bpfilter.sh; } | sha256sum | cut -c1-12)
IMAGE=localhost/bpyfilter-build:$HASH

if [ -n "${FORCE:-}" ] || ! podman image exists "$IMAGE"; then
  echo "--- building $IMAGE: bpfilter $REF on $BASE" >&2
  CTX=$(mktemp -d)
  trap 'rm -rf "$CTX"' EXIT
  cp ci/build-bpfilter.sh "$CTX/"
  cat > "$CTX/Containerfile" <<EOF
FROM $BASE
COPY build-bpfilter.sh /tmp/
RUN BPFILTER_REF='$REF' bash /tmp/build-bpfilter.sh && rm /tmp/build-bpfilter.sh
EOF
  # --no-cache with FORCE: a branch ref (main) has new commits under the same name.
  podman build ${FORCE:+--no-cache} --label bpyfilter-build=1 -t "$IMAGE" "$CTX" >&2
  # Images for other refs or scripts: only this one is used from now on.
  podman images --filter label=bpyfilter-build=1 --format '{{.Repository}}:{{.Tag}}' \
    | grep -v -x "$IMAGE" | xargs -r podman rmi >&2 || true
fi
echo "$IMAGE"
