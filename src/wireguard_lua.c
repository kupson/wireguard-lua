/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <lua.h>
#include <lauxlib.h>

#include "wireguard.h"

#define WG_KEY_LEN 32

#if LUA_VERSION_NUM == 501
#define lua_rawlen lua_objlen
#ifndef luaL_newlib
#define luaL_newlib(L, l) (lua_newtable((L)), luaL_register((L), NULL, (l)))
#endif
#endif

static int abs_index(lua_State *L, int idx)
{
	if (idx > 0 || idx <= LUA_REGISTRYINDEX)
		return idx;
	return lua_gettop(L) + idx + 1;
}

static int push_errno_result(lua_State *L)
{
	int e = errno;
	lua_pushnil(L);
	lua_pushstring(L, strerror(e));
	lua_pushinteger(L, e);
	return 3;
}

static int push_error_result(lua_State *L, int e)
{
	lua_pushnil(L);
	lua_pushstring(L, strerror(e));
	lua_pushinteger(L, e);
	return 3;
}

static int check_key_base64(lua_State *L, int idx, wg_key key)
{
	const char *s = luaL_checkstring(L, idx);
	if (wg_key_from_base64(key, s) < 0)
		return luaL_error(L, "invalid WireGuard base64 key");
	return 0;
}

static void push_key_base64(lua_State *L, const wg_key key)
{
	wg_key_b64_string s;
	wg_key_to_base64(s, key);
	lua_pushstring(L, s);
}

static bool get_bool_field(lua_State *L, int idx, const char *name)
{
	bool ret;
	lua_getfield(L, idx, name);
	ret = lua_toboolean(L, -1) ? true : false;
	lua_pop(L, 1);
	return ret;
}

static bool get_u16_field(lua_State *L, int idx, const char *name, uint16_t *out)
{
	lua_Integer value;
	lua_getfield(L, idx, name);
	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);
		return false;
	}
	value = luaL_checkinteger(L, -1);
	if (value < 0 || value > UINT16_MAX)
		luaL_error(L, "field '%s' out of uint16 range", name);
	*out = (uint16_t)value;
	lua_pop(L, 1);
	return true;
}

static bool get_u32_field(lua_State *L, int idx, const char *name, uint32_t *out)
{
	lua_Integer value;
	lua_getfield(L, idx, name);
	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);
		return false;
	}
	if (lua_isboolean(L, -1) && !lua_toboolean(L, -1)) {
		*out = 0;
		lua_pop(L, 1);
		return true;
	}
	value = luaL_checkinteger(L, -1);
	if (value < 0 || value > UINT32_MAX)
		luaL_error(L, "field '%s' out of uint32 range", name);
	*out = (uint32_t)value;
	lua_pop(L, 1);
	return true;
}

static bool get_key_field(lua_State *L, int idx, const char *name, wg_key key, bool allow_false_zero)
{
	lua_getfield(L, idx, name);
	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);
		return false;
	}
	if (allow_false_zero && lua_isboolean(L, -1) && !lua_toboolean(L, -1)) {
		memset(key, 0, WG_KEY_LEN);
		lua_pop(L, 1);
		return true;
	}
	check_key_base64(L, -1, key);
	lua_pop(L, 1);
	return true;
}

static void append_peer(wg_device *dev, wg_peer *peer)
{
	if (!dev->first_peer)
		dev->first_peer = peer;
	else
		dev->last_peer->next_peer = peer;
	dev->last_peer = peer;
}

static void append_allowedip(wg_peer *peer, wg_allowedip *allowedip)
{
	if (!peer->first_allowedip)
		peer->first_allowedip = allowedip;
	else
		peer->last_allowedip->next_allowedip = allowedip;
	peer->last_allowedip = allowedip;
}

static int parse_allowedip(lua_State *L, const char *s, wg_allowedip *allowedip)
{
	char buf[INET6_ADDRSTRLEN + 8];
	char *slash;
	int family;
	unsigned long cidr;
	char *end = NULL;

	if (strlen(s) >= sizeof(buf))
		return luaL_error(L, "allowed IP is too long: %s", s);
	strcpy(buf, s);

	slash = strchr(buf, '/');
	if (slash) {
		*slash++ = '\0';
		if (*slash == '\0')
			return luaL_error(L, "missing CIDR after slash in allowed IP: %s", s);
		cidr = strtoul(slash, &end, 10);
		if (*end != '\0')
			return luaL_error(L, "invalid CIDR in allowed IP: %s", s);
	} else {
		cidr = strchr(buf, ':') ? 128 : 32;
	}

	family = strchr(buf, ':') ? AF_INET6 : AF_INET;
	allowedip->family = family;
	allowedip->cidr = (uint8_t)cidr;

	if (family == AF_INET) {
		if (cidr > 32)
			return luaL_error(L, "IPv4 CIDR out of range in allowed IP: %s", s);
		if (inet_pton(AF_INET, buf, &allowedip->ip4) != 1)
			return luaL_error(L, "invalid IPv4 allowed IP: %s", s);
	} else {
		if (cidr > 128)
			return luaL_error(L, "IPv6 CIDR out of range in allowed IP: %s", s);
		if (inet_pton(AF_INET6, buf, &allowedip->ip6) != 1)
			return luaL_error(L, "invalid IPv6 allowed IP: %s", s);
	}

	return 0;
}

static int parse_endpoint(lua_State *L, const char *s, wg_endpoint *endpoint)
{
	char host[NI_MAXHOST];
	char service[NI_MAXSERV];
	const char *port;
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	int ret;

	memset(endpoint, 0, sizeof(*endpoint));

	if (s[0] == '[') {
		const char *end = strchr(s, ']');
		size_t len;
		if (!end || end[1] != ':')
			return luaL_error(L, "IPv6 endpoints must look like [addr]:port");
		len = (size_t)(end - s - 1);
		if (len == 0 || len >= sizeof(host))
			return luaL_error(L, "invalid endpoint host");
		memcpy(host, s + 1, len);
		host[len] = '\0';
		port = end + 2;
	} else {
		const char *colon = strrchr(s, ':');
		size_t len;
		if (!colon)
			return luaL_error(L, "endpoint must look like host:port");
		if (strchr(s, ':') != colon)
			return luaL_error(L, "unbracketed IPv6 endpoints are ambiguous; use [addr]:port");
		len = (size_t)(colon - s);
		if (len == 0 || len >= sizeof(host))
			return luaL_error(L, "invalid endpoint host");
		memcpy(host, s, len);
		host[len] = '\0';
		port = colon + 1;
	}

	if (*port == '\0')
		return luaL_error(L, "endpoint port is empty");

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	ret = getaddrinfo(host, port, &hints, &res);
	if (ret != 0)
		return luaL_error(L, "cannot resolve endpoint '%s': %s", s, gai_strerror(ret));

	if (res->ai_addrlen > sizeof(*endpoint)) {
		freeaddrinfo(res);
		return luaL_error(L, "resolved endpoint address is too large");
	}
	memcpy(&endpoint->addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return 0;
}

static void push_endpoint(lua_State *L, const wg_endpoint *endpoint)
{
	char host[NI_MAXHOST];
	char service[NI_MAXSERV];
	int ret;

	if (endpoint->addr.sa_family != AF_INET && endpoint->addr.sa_family != AF_INET6) {
		lua_pushnil(L);
		return;
	}

	ret = getnameinfo(&endpoint->addr, endpoint->addr.sa_family == AF_INET ?
			 sizeof(endpoint->addr4) : sizeof(endpoint->addr6),
			 host, sizeof(host), service, sizeof(service),
			 NI_NUMERICHOST | NI_NUMERICSERV);
	if (ret != 0) {
		lua_pushnil(L);
		return;
	}

	if (endpoint->addr.sa_family == AF_INET6) {
		char buf[NI_MAXHOST + NI_MAXSERV + 4];
		snprintf(buf, sizeof(buf), "[%s]:%s", host, service);
		lua_pushstring(L, buf);
	} else {
		char buf[NI_MAXHOST + NI_MAXSERV + 2];
		snprintf(buf, sizeof(buf), "%s:%s", host, service);
		lua_pushstring(L, buf);
	}
}

static void push_allowedip(lua_State *L, const wg_allowedip *allowedip)
{
	char addr[INET6_ADDRSTRLEN];
	char buf[INET6_ADDRSTRLEN + 8];

	if (allowedip->family == AF_INET)
		inet_ntop(AF_INET, &allowedip->ip4, addr, sizeof(addr));
	else if (allowedip->family == AF_INET6)
		inet_ntop(AF_INET6, &allowedip->ip6, addr, sizeof(addr));
	else {
		lua_pushnil(L);
		return;
	}

	snprintf(buf, sizeof(buf), "%s/%u", addr, allowedip->cidr);
	lua_pushstring(L, buf);
}

static void push_device(lua_State *L, const wg_device *dev)
{
	wg_peer *peer;
	int peer_i = 1;

	lua_newtable(L);

	lua_pushstring(L, dev->name);
	lua_setfield(L, -2, "name");
	lua_pushinteger(L, dev->ifindex);
	lua_setfield(L, -2, "ifindex");

	if (dev->flags & WGDEVICE_HAS_PUBLIC_KEY) {
		push_key_base64(L, dev->public_key);
		lua_setfield(L, -2, "public_key");
	}
	if (dev->flags & WGDEVICE_HAS_PRIVATE_KEY) {
		push_key_base64(L, dev->private_key);
		lua_setfield(L, -2, "private_key");
	}
	if (dev->flags & WGDEVICE_HAS_LISTEN_PORT) {
		lua_pushinteger(L, dev->listen_port);
		lua_setfield(L, -2, "listen_port");
	}
	if (dev->flags & WGDEVICE_HAS_FWMARK) {
		lua_pushinteger(L, dev->fwmark);
		lua_setfield(L, -2, "fwmark");
	}

	lua_newtable(L);
	wg_for_each_peer(dev, peer) {
		wg_allowedip *allowedip;
		int allowed_i = 1;

		lua_newtable(L);
		push_key_base64(L, peer->public_key);
		lua_setfield(L, -2, "public_key");

		if (!wg_key_is_zero(peer->preshared_key)) {
			push_key_base64(L, peer->preshared_key);
			lua_setfield(L, -2, "preshared_key");
		}

		push_endpoint(L, &peer->endpoint);
		lua_setfield(L, -2, "endpoint");

		lua_pushinteger(L, peer->persistent_keepalive_interval);
		lua_setfield(L, -2, "persistent_keepalive_interval");
		lua_pushnumber(L, (lua_Number)peer->last_handshake_time.tv_sec);
		lua_setfield(L, -2, "last_handshake_time_sec");
		lua_pushnumber(L, (lua_Number)peer->last_handshake_time.tv_nsec);
		lua_setfield(L, -2, "last_handshake_time_nsec");
		lua_pushnumber(L, (lua_Number)peer->rx_bytes);
		lua_setfield(L, -2, "rx_bytes");
		lua_pushnumber(L, (lua_Number)peer->tx_bytes);
		lua_setfield(L, -2, "tx_bytes");

		lua_newtable(L);
		wg_for_each_allowedip(peer, allowedip) {
			push_allowedip(L, allowedip);
			lua_rawseti(L, -2, allowed_i++);
		}
		lua_setfield(L, -2, "allowed_ips");

		lua_rawseti(L, -2, peer_i++);
	}
	lua_setfield(L, -2, "peers");
}

static void parse_allowedips(lua_State *L, int idx, wg_peer *peer)
{
	size_t i, n;
	idx = abs_index(L, idx);

	lua_getfield(L, idx, "allowed_ips");
	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);
		return;
	}
	luaL_checktype(L, -1, LUA_TTABLE);
	n = lua_rawlen(L, -1);
	for (i = 1; i <= n; ++i) {
		wg_allowedip *allowedip = calloc(1, sizeof(*allowedip));
		if (!allowedip)
			luaL_error(L, "out of memory");
		lua_rawgeti(L, -1, (int)i);
		parse_allowedip(L, luaL_checkstring(L, -1), allowedip);
		lua_pop(L, 1);
		append_allowedip(peer, allowedip);
	}
	lua_pop(L, 1);
}

static wg_peer *parse_peer(lua_State *L, int idx)
{
	wg_peer *peer;
	uint16_t keepalive;
	idx = abs_index(L, idx);

	luaL_checktype(L, idx, LUA_TTABLE);
	peer = calloc(1, sizeof(*peer));
	if (!peer)
		luaL_error(L, "out of memory");

	if (!get_key_field(L, idx, "public_key", peer->public_key, false))
		luaL_error(L, "peer.public_key is required");
	peer->flags |= WGPEER_HAS_PUBLIC_KEY;

	if (get_bool_field(L, idx, "remove"))
		peer->flags |= WGPEER_REMOVE_ME;
	if (get_bool_field(L, idx, "replace_allowed_ips"))
		peer->flags |= WGPEER_REPLACE_ALLOWEDIPS;
	if (get_key_field(L, idx, "preshared_key", peer->preshared_key, true))
		peer->flags |= WGPEER_HAS_PRESHARED_KEY;
	if (get_u16_field(L, idx, "persistent_keepalive_interval", &keepalive)) {
		peer->persistent_keepalive_interval = keepalive;
		peer->flags |= WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL;
	}

	lua_getfield(L, idx, "endpoint");
	if (!lua_isnil(L, -1))
		parse_endpoint(L, luaL_checkstring(L, -1), &peer->endpoint);
	lua_pop(L, 1);

	parse_allowedips(L, idx, peer);
	return peer;
}

static wg_device *parse_device(lua_State *L, int idx)
{
	wg_device *dev;
	const char *name;
	uint16_t listen_port;
	uint32_t fwmark;
	size_t i, n;

	idx = abs_index(L, idx);
	luaL_checktype(L, idx, LUA_TTABLE);
	dev = calloc(1, sizeof(*dev));
	if (!dev)
		luaL_error(L, "out of memory");

	lua_getfield(L, idx, "name");
	name = luaL_checkstring(L, -1);
	if (strlen(name) >= sizeof(dev->name))
		luaL_error(L, "device name is too long");
	strcpy(dev->name, name);
	lua_pop(L, 1);

	if (get_bool_field(L, idx, "replace_peers"))
		dev->flags |= WGDEVICE_REPLACE_PEERS;
	if (get_key_field(L, idx, "private_key", dev->private_key, true))
		dev->flags |= WGDEVICE_HAS_PRIVATE_KEY;
	if (get_u16_field(L, idx, "listen_port", &listen_port)) {
		dev->listen_port = listen_port;
		dev->flags |= WGDEVICE_HAS_LISTEN_PORT;
	}
	if (get_u32_field(L, idx, "fwmark", &fwmark)) {
		dev->fwmark = fwmark;
		dev->flags |= WGDEVICE_HAS_FWMARK;
	}

	lua_getfield(L, idx, "peers");
	if (!lua_isnil(L, -1)) {
		luaL_checktype(L, -1, LUA_TTABLE);
		n = lua_rawlen(L, -1);
		for (i = 1; i <= n; ++i) {
			wg_peer *peer;
			lua_rawgeti(L, -1, (int)i);
			peer = parse_peer(L, -1);
			lua_pop(L, 1);
			append_peer(dev, peer);
		}
	}
	lua_pop(L, 1);
	return dev;
}

static int l_generate_private_key(lua_State *L)
{
	wg_key key;
	wg_generate_private_key(key);
	push_key_base64(L, key);
	return 1;
}

static int l_generate_preshared_key(lua_State *L)
{
	wg_key key;
	wg_generate_preshared_key(key);
	push_key_base64(L, key);
	return 1;
}

static int l_public_key(lua_State *L)
{
	wg_key private_key, public_key;
	check_key_base64(L, 1, private_key);
	wg_generate_public_key(public_key, private_key);
	push_key_base64(L, public_key);
	return 1;
}

static int l_key_is_zero(lua_State *L)
{
	wg_key key;
	check_key_base64(L, 1, key);
	lua_pushboolean(L, wg_key_is_zero(key));
	return 1;
}

static int l_list_devices(lua_State *L)
{
	char *names, *name;
	size_t len;
	int i = 1;

	names = wg_list_device_names();
	if (!names)
		return push_errno_result(L);

	lua_newtable(L);
	wg_for_each_device_name(names, name, len) {
		lua_pushlstring(L, name, len);
		lua_rawseti(L, -2, i++);
	}
	free(names);
	return 1;
}

static int l_add_device(lua_State *L)
{
	const char *name = luaL_checkstring(L, 1);
	if (wg_add_device(name) < 0)
		return push_errno_result(L);
	lua_pushboolean(L, 1);
	return 1;
}

static int l_del_device(lua_State *L)
{
	const char *name = luaL_checkstring(L, 1);
	if (wg_del_device(name) < 0)
		return push_errno_result(L);
	lua_pushboolean(L, 1);
	return 1;
}

static int l_get_device(lua_State *L)
{
	const char *name = luaL_checkstring(L, 1);
	wg_device *dev = NULL;

	if (wg_get_device(&dev, name) < 0)
		return push_errno_result(L);
	push_device(L, dev);
	wg_free_device(dev);
	return 1;
}

static int l_set_device(lua_State *L)
{
	wg_device *dev = parse_device(L, 1);
	int ret;

	ret = wg_set_device(dev);
	if (ret < 0) {
		int e = errno;
		wg_free_device(dev);
		return push_error_result(L, e);
	}
	wg_free_device(dev);
	lua_pushboolean(L, 1);
	return 1;
}

static const luaL_Reg wireguard_funcs[] = {
	{ "generate_private_key", l_generate_private_key },
	{ "generate_preshared_key", l_generate_preshared_key },
	{ "public_key", l_public_key },
	{ "key_is_zero", l_key_is_zero },
	{ "list_devices", l_list_devices },
	{ "add_device", l_add_device },
	{ "del_device", l_del_device },
	{ "get_device", l_get_device },
	{ "set_device", l_set_device },
	{ NULL, NULL }
};

int luaopen_wireguard(lua_State *L)
{
	luaL_newlib(L, wireguard_funcs);
	return 1;
}
