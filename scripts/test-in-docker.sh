#!/bin/sh
set -eu

image=${DOCKER_TEST_IMAGE:-wireguard-lua-test:bookworm}
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

docker build \
	-t "$image" \
	-f "$repo_root/docker/test/Dockerfile" \
	"$repo_root"

docker run --rm \
	--cap-add NET_ADMIN \
	-v "$repo_root:/work" \
	-w /work \
	"$image" \
	sh scripts/test-in-container.sh
