#
# Copyright (C) 2015 Rafał Miłecki <zajec5@gmail.com>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=tcpcap
PKG_RELEASE:=1

PKG_FLAGS:=nonshared

include $(INCLUDE_DIR)/package.mk

define Package/tcpcap
  SECTION:=utils
  CATEGORY:=Base system
  TITLE:= Tcp packet capter
  DEPENDS:=+libpcap +libpthread +libc
endef

define Package/tcpcap/description
 This package is use tcp packet capter.
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS) -Wall"
endef

define Package/tcpcap/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mainApp $(1)/usr/bin/
endef

$(eval $(call BuildPackage,tcpcap))
