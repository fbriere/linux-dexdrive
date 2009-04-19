#!/usr/bin/make -f

ifneq ($(KERNELRELEASE),)
# Call from kernel build system

obj-m := dexdrive.o

else
# Normal Makefile


CFLAGS = -O2 -g -Wall

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)


all: attach modules

attach: dexdrive.h

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	rm -rf attach
	-$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	# These are left behind by the Linux Makefile
	rm -f Module.markers modules.order


.PHONY:	all modules clean

endif


