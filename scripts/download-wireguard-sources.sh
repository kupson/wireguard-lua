#!/bin/sh
set -eu

required_metadata="PKG_VERSION PKG_SOURCE PKG_SOURCE_URL PKG_HASH"
wireguard_library_dir="contrib/embeddable-wg-library"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(dirname -- "$script_dir")

root_makefile=${ROOT_MAKEFILE:-Makefile}
case "$root_makefile" in
	/*) ;;
	*) root_makefile="$repo_root/$root_makefile" ;;
esac

src_dir=${SRC_DIR:-src}
case "$src_dir" in
	/*) ;;
	*) src_dir="$repo_root/$src_dir" ;;
esac

if [ ! -f "$root_makefile" ]; then
	echo "error: Makefile is required and must define OpenWrt package metadata: $required_metadata" >&2
	exit 1
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT INT HUP TERM

metadata_file="$tmpdir/pkg-metadata.mk"
query_makefile="$tmpdir/query.mk"

grep -E '^[[:space:]]*PKG_[A-Za-z0-9_]*[[:space:]]*[:?+]?=' "$root_makefile" > "$metadata_file" || true

cat > "$query_makefile" <<'EOF'
include $(METADATA_FILE)

.PHONY: print
print:
	@$(foreach var,$(REQUIRED_METADATA),printf '%s=%s\n' '$(var)' '$($(var))';)
EOF

metadata=$(
	make -s -f "$query_makefile" print \
		METADATA_FILE="$metadata_file" \
		REQUIRED_METADATA="$required_metadata"
)

eval "$metadata"

missing=
for name in $required_metadata; do
	eval "value=\${$name:-}"
	if [ -z "$value" ]; then
		missing="$missing $name"
	fi
done

if [ -n "$missing" ]; then
	echo "error: Makefile is missing required OpenWrt package metadata:$missing" >&2
	exit 1
fi

archive="$tmpdir/$PKG_SOURCE"
curl -fsSL "$PKG_SOURCE_URL$PKG_SOURCE" -o "$archive"

if command -v sha256sum >/dev/null 2>&1; then
	actual_hash=$(sha256sum "$archive" | sed 's/[[:space:]].*//')
else
	actual_hash=$(shasum -a 256 "$archive" | sed 's/[[:space:]].*//')
fi

if [ "$actual_hash" != "$PKG_HASH" ]; then
	echo "error: hash mismatch for $PKG_SOURCE" >&2
	echo "expected: $PKG_HASH" >&2
	echo "actual:   $actual_hash" >&2
	exit 1
fi

mkdir -p "$src_dir"
tar -xJf "$archive" -C "$tmpdir" \
	"wireguard-tools-$PKG_VERSION/$wireguard_library_dir/wireguard.c" \
	"wireguard-tools-$PKG_VERSION/$wireguard_library_dir/wireguard.h"

cp "$tmpdir/wireguard-tools-$PKG_VERSION/$wireguard_library_dir/wireguard.c" "$src_dir/wireguard.c"
cp "$tmpdir/wireguard-tools-$PKG_VERSION/$wireguard_library_dir/wireguard.h" "$src_dir/wireguard.h"

echo "Downloaded and extracted WireGuard embeddable library sources into $src_dir/"
