# Lua bindings for WireGuard® device configuration

## Development / Docker

### Preflight

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

## OpenWRT

The extensionless root `Makefile` is reserved for OpenWrt package integration.
See the upstream [OpenWrt package guide](https://openwrt.org/docs/guide-developer/packages)
for general package buildroot workflow.

To build it from an OpenWrt buildroot, copy this directory into the package
tree:

```sh
cp -a wireguard-lua /path/to/openwrt/package/lang/wireguard-lua
```

Then run this from the OpenWrt buildroot root:

```sh
make package/lang/wireguard-lua/compile CONFIG_PACKAGE_wireguard-lua=m
```

The Docker development makefile is separate and should be invoked explicitly as
`Makefile.docker`.

## Lua API

```lua
local wg = require "wireguard"

local private = wg.generate_private_key()
local peer_private = wg.generate_private_key()
local peer_public = wg.public_key(peer_private)
local psk = wg.generate_preshared_key()
local devices, err, errno = wg.list_devices()

assert(wg.add_device("wgtest"))
assert(wg.set_device{
  name = "wgtest",
  private_key = private,
  listen_port = 51820,
  replace_peers = true,
  peers = {
    {
      public_key = peer_public,
      preshared_key = psk,
      endpoint = "192.0.2.1:51820",
      persistent_keepalive_interval = 25,
      replace_allowed_ips = true,
      allowed_ips = { "10.0.0.2/32", "fd00::2/128" }
    }
  }
})

local dev = assert(wg.get_device("wgtest"))
assert(wg.del_device("wgtest"))
```

## Trademark

"[WireGuard](https://www.wireguard.com/)" and the "WireGuard" logo are
registered trademarks of Jason A. Donenfeld. See the
[WireGuard trademark policy](https://www.wireguard.com/trademark-policy/).
