# Development / Docker

## Preflight

The Docker development workflow uses `Makefile.docker` instead of the root
`Makefile`. The root `Makefile` is still required, because the
`scripts/download-wireguard-sources.sh` helper copies the root `PKG_*`
assignments into a temporary make fragment. The download target requires these
values:

- `PKG_VERSION`
- `PKG_SOURCE`
- `PKG_SOURCE_URL`
- `PKG_HASH`

Download the WireGuard embeddable library sources with:

```sh
make -f Makefile.docker download
```

The script verifies the archive SHA-256 hash before extraction. The downloaded
archive and temporary metadata fragment are removed after the target exits.

The generated upstream files are extracted into `src/`:

- `src/wireguard.c`
- `src/wireguard.h`

Those generated files are ignored by git. They are present only so
`src/Makefile` can build the Lua module during local or Docker development.

Run the Lua binding tests with:

```sh
make -f Makefile.docker test
```

The test target builds and reuses `docker/test/Dockerfile`. It runs Docker with
`--cap-add NET_ADMIN`, so the Docker host or VM must expose WireGuard kernel
support.

# OpenWRT

The extensionless root `Makefile` is reserved for OpenWrt package integration.
It is intentionally not replaced by `Makefile.docker`, and `Makefile.docker`
does not include it as make syntax. Instead, the Docker development makefile
delegates to `scripts/download-wireguard-sources.sh`, which extracts the root
`PKG_*` assignments into a temporary make fragment for downloading and verifying
the WireGuard tools source archive.
