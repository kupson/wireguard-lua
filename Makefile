#
# WireGuard Lua bindings for OpenWrt
#

include $(TOPDIR)/rules.mk

PKG_NAME:=wireguard-lua
PKG_VERSION:=1.0.20260223
PKG_RELEASE:=1

PKG_SOURCE:=wireguard-tools-$(PKG_VERSION).tar.xz
PKG_SOURCE_URL:=https://git.zx2c4.com/wireguard-tools/snapshot/
PKG_HASH:=af459827b80bfd31b83b08077f4b5843acb7d18ad9a33a2ef532d3090f291fbf

PKG_LICENSE:=LGPL-2.1-or-later
PKG_MAINTAINER:=Rafal Kupka <r.kupson@gmail.com>
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/wireguard-lua
  SUBMENU:=Lua
  SECTION:=lang
  CATEGORY:=Languages
  TITLE:=Lua bindings for WireGuard device configuration
  URL:=https://www.wireguard.com/
  DEPENDS:=+lua
endef

define Package/wireguard-lua/description
  Lua 5.1/LuaJIT-compatible bindings for Linux WireGuard devices using
  WireGuard's embeddable C library from the wireguard-tools source tree.
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	$(TAR) -C $(PKG_BUILD_DIR) --strip-components=1 -xJf $(DL_DIR)/$(PKG_SOURCE)
	$(CP) ./src/wireguard_lua.c $(PKG_BUILD_DIR)/contrib/embeddable-wg-library/
	$(CP) ./src/Makefile $(PKG_BUILD_DIR)/contrib/embeddable-wg-library/Makefile.lua
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/contrib/embeddable-wg-library -f Makefile.lua \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CPPFLAGS) $(TARGET_CFLAGS) $(FPIC) -std=gnu99 -Wall -Wextra" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		LUA_CFLAGS="-I$(STAGING_DIR)/usr/include" \
		LUA_LIBS=""
endef

define Package/wireguard-lua/install
	$(INSTALL_DIR) $(1)/usr/lib/lua
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/contrib/embeddable-wg-library/wireguard.so $(1)/usr/lib/lua/
endef

$(eval $(call BuildPackage,wireguard-lua))
