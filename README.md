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

Load the module with:

```lua
local wg = require "wireguard"
```

WireGuard keys are base64 strings in the standard 44-character WireGuard key
format. Invalid key strings raise a Lua error. Kernel operations return `true`
or a result table on success, and `nil, message, errno` on failure.

### Key functions

- `generate_private_key() -> private_key`
  Returns a new private key string.
- `generate_preshared_key() -> preshared_key`
  Returns a new preshared key string.
- `public_key(private_key) -> public_key`
  Derives a public key string from `private_key`.
- `key_is_zero(key) -> boolean`
  Returns whether `key` is the all-zero WireGuard key.

### Device functions

- `list_devices() -> { name, ... } | nil, message, errno`
  Returns an array of WireGuard interface names.
- `add_device(name) -> true | nil, message, errno`
  Creates a WireGuard interface.
- `del_device(name) -> true | nil, message, errno`
  Deletes a WireGuard interface.
- `get_device(name) -> device | nil, message, errno`
  Reads WireGuard interface configuration and runtime state.
- `set_device(device) -> true | nil, message, errno`
  Applies WireGuard configuration from a device table.

The `set_device()` table accepts:

- `name` string, required.
- `private_key` key string, optional. Use `false` to clear it.
- `listen_port` integer from `0` to `65535`, optional.
- `fwmark` integer from `0` to `4294967295`, optional. Use `false` to clear it.
- `replace_peers` boolean, optional.
- `peers` array of peer tables, optional.

Each peer table accepts:

- `public_key` key string, required.
- `preshared_key` key string, optional. Use `false` to clear it.
- `endpoint` string as `host:port` or `[ipv6-host]:port`, optional.
- `persistent_keepalive_interval` integer from `0` to `65535`, optional.
- `replace_allowed_ips` boolean, optional.
- `remove` boolean, optional.
- `allowed_ips` array of CIDR strings, optional. Plain IPv4 and IPv6 addresses
  default to `/32` and `/128`.

`get_device()` returns a device table with:

- `name` string.
- `ifindex` integer.
- `public_key`, `private_key`, `listen_port`, and `fwmark` when reported by the
  kernel.
- `peers` array.

Each returned peer contains:

- `public_key` string.
- `preshared_key` string when configured.
- `endpoint` string or `nil`.
- `persistent_keepalive_interval` integer.
- `last_handshake_time_sec` and `last_handshake_time_nsec` numbers.
- `rx_bytes` and `tx_bytes` numbers.
- `allowed_ips` array of CIDR strings.

Example:

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
