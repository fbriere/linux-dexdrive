#!/usr/bin/make -f

ifneq ($(KERNELRELEASE),)
# Call from kernel build system

obj-m := dexdrive.o

else
# Normal Makefile


CFLAGS = -O2 -g -Wall

PREFIX = /usr/local

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)


all: dexattach modules

dexattach: dexdrive.h

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

install: all
	cp dexattach $(DESTDIR)/$(PREFIX)/bin
	$(MAKE) -C $(KERNELDIR) M=$(PWD) INSTALL_MOD_PATH=$(abspath $(DESTDIR)) modules_install

clean:
	rm -rf dexattach
	-$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	# These are left behind by the Linux Makefile
	rm -f Module.markers modules.order


.PHONY:	all modules clean

endif


