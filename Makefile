#!/usr/bin/make -f

EXTRA_CFLAGS = -O -g -Wall

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

clean:
	rm -rf *.o *~ core .*.cmd *.ko *.mod.c .tmp_versions Module.markers Module.symvers modules.order

.PHONY:	all modules clean

