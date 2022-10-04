SHELL=/bin/bash

VERSION := $(shell git describe --tags --abbrev=0)

all: debian openwrt

openwrt: binary
	@echo "Building openwrt package"
	$(eval TMP := $(shell mktemp -d))
	@mkdir -p $(TMP)/root/usr/sbin
	cp mlx4_br $(TMP)/root/usr/sbin/ -af
	chmod +x $(TMP)/root/usr/sbin/mlx4_br
	@mkdir -p $(TMP)/root/etc/init.d
	cp package/openwrt/mlx4_br $(TMP)/root/etc/init.d/ -af
	chmod +x $(TMP)/root/etc/init.d/mlx4_br
	tar --owner=root --group=root -zcf $(TMP)/data.tar.gz -C $(TMP)/root .
	cp package/openwrt/control $(TMP)/control -af
	chmod +x $(TMP)/control/*
	sed -i "s/Version:.*/Version: $(VERSION)/" $(TMP)/control/control
	tar --owner=root --group=root -zcf $(TMP)/control.tar.gz -C $(TMP)/control .
	cp package/openwrt/debian-binary $(TMP)/debian-binary -af
	rm -rf $(TMP)/root
	rm -rf $(TMP)/control
	tar --owner=root --group=root -zcf mlx4_br_$(VERSION)_x86-64.ipk -C $(TMP) .
	rm -rf $(TMP)
	@echo "Cleanup openwrt package"

debian: binary
	@echo "Building debian package"
	$(eval TMP := $(shell mktemp -d))
	@mkdir -p $(TMP)/usr/sbin
	cp mlx4_br $(TMP)/usr/sbin/ -af
	chmod +x $(TMP)/usr/sbin/mlx4_br
	@mkdir -p $(TMP)/lib/systemd/system
	cp package/debian/mlx4_br.service $(TMP)/lib/systemd/system/ -af
	cp package/debian/DEBIAN $(TMP)/ -raf
	sed -i "s/Version:.*/Version: $(VERSION)/" $(TMP)/DEBIAN/control
	dpkg-deb -b -Zgzip $(TMP) mlx4_br.$(VERSION).deb
	rm -rf $(TMP)
	@echo "Cleanup debian package"
	

binary:
	$(CXX) main.cc -std=c++17 -Wno-ignored-attributes -static -s -fno-exceptions -fno-rtti -Os -flto -fdata-sections -ffunction-sections -Wl,--gc-sections -lstdc++ -o mlx4_br
	upx -9 mlx4_br

.PHONY: clean
clean:
	rm -f mlx4_br
