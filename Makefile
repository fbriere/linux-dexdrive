#!/usr/bin/make -f

ifneq ($(KERNELRELEASE),)
# call from kernel build system

obj-m := dexdrive.o

else

CFLAGS += -O2 -g -Wall

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

endif


all: attach

attach: dexdrive.h

clean:
	rm -rf *.o *~ core .*.cmd *.ko *.mod.c .tmp_versions Module.markers Module.symvers modules.order attach

.PHONY:	all modules clean

