#!/usr/bin/make -f

KDIR = /var/tmp/1/linux-source-2.6.18

VERSIONFILE = $(KDIR)/include/linux/version.h
VERSION  = $(shell awk -F\" '/REL/ {print $$2}' $(VERSIONFILE))
INSTALLDIR = /lib/modules/$(VERSION)/misc

include $(KDIR)/.config

CFLAGS = -D__KERNEL__ -DMODULE -I$(KDIR)/include -O -Wall

all: dexdrive.o attach

install:
	install -d $(INSTALLDIR)
	install -c dexdrive.o $(INSTALLDIR)

clean:
	rm -f *.o *~ core

.PHONY:	all install clean

