#!/bin/sh
set -eu

trap 'make -C src clean >/dev/null 2>&1 || true' EXIT INT HUP TERM

make -f Makefile.docker download
make -C src clean
make -C src LUA_CFLAGS="$(pkg-config --cflags lua5.1)" LUA_LIBS="$(pkg-config --libs lua5.1)"
LUA_CPATH="/work/src/?.so;;" busted --lua=lua5.1 tests
