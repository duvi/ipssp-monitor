#
# Copyright (C) 2018-2019 Varga David, InnoBova Kft. <varga.david@duvinet.hu>
#
# This is free software, licensed under the Apache 2 license.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=ipssp
PKG_RELEASE:=1
PKG_LICENSE:=Apache-2.0

include $(INCLUDE_DIR)/package.mk


define Package/ipssp
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Simple radiotap capture utility
  MAINTAINER:=Varga David <varga.david@duvinet.hu>
endef

define Package/ipssp/description
  The ipssp utility receives radiotap packet data from wifi monitor interfaces
  and outputs it to pcap format. It gathers recived packets in a fixed ring
  buffer to dump them on demand which is useful for background monitoring.
  Alternatively the utility can stream the data to stdout to act as remote
  capture drone for Wireshark or similar programs.
endef


define Build/Configure
endef

ifeq ($(CONFIG_PACKAGE_kmod-ath9k),y)
TARGET_CFLAGS += -DHAVE_ATH9K
endif

ifeq ($(CONFIG_PACKAGE_kmod-mt76x2),y)
TARGET_CFLAGS += -DHAVE_MT76X2
endif

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) \
		-o $(PKG_BUILD_DIR)/ipssp $(PKG_BUILD_DIR)/ipssp.c
endef


define Package/ipssp/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ipssp $(1)/usr/sbin/ipssp
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/ipssp.init $(1)/etc/init.d/ipssp
endef

$(eval $(call BuildPackage,ipssp))
