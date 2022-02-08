[![Build](https://github.com/fbriere/linux-dexdrive/actions/workflows/main.yml/badge.svg)](https://github.com/fbriere/linux-dexdrive/actions/workflows/main.yml)

Linux block driver for the DexDrive
===================================

The DexDrive is a device that connects via the serial port, and allows access
to PlayStation or Nintendo 64 memory cards (depending on the model).  This
Linux driver provides block device functionality for the DexDrive, making it
possible to format/mount a memory card like any other block device.

This driver was written mostly as a personal challenge, and not out of any
need or usefulness.  After all, a regular PlayStation memory card holds a mere
128 KiB of data, and a Nintendo 64 Controller Pak holds a whopping 32 KiB.
While these figures weren't too laughable ten years ago, nowadays you can get
much larger (and faster) USB sticks for free with your breakfast cereal.

(But hey, if something can be done, why bother with such mundane details as
whether or not it would make any sense?)

Please note that if you're merely looking for a way to read/write memory
cards, this driver is overkill.  Instead, you may want to look at [Dexux](
http://dexux.sourceforge.net/), an application/library that does just that.


COMPILATION
-----------

Compiling this module requires a fully configured kernel source tree.  By
default, simply running `make` will compile against the source tree of the
currently running kernel.  If this is not appropriate, you can specify the
location of your kernel source tree:

    $ make KERNELDIR=/usr/src/linux

This will compile the `dexdrive.ko` kernel module, as well as the `dexattach`
utility.  You can install them both with `make install`, with an optional
`DESTDIR` argument if you don't want to install them as root.


USAGE
-----

After loading the dexdrive module (with `insmod` or `modprobe`) and connecting a
DexDrive to a serial port, the block device is created by running dexattach on
that serial port:

    $ dexattach --check --verbose /dev/ttyS0
    Opening /dev/ttyS0 and setting line discipline
    Device number is 254:0

(If you get a `Cannot set line discipline: Invalid argument` error, it is most
likely that the dexdrive module isn't loaded.)

If you are running udev, a block device entry will be automatically created as
`/dev/dexdrive0`.  If you are not running udev, you will need to create that
entry yourself, as root:

    # mknod --mode=0660 /dev/dexdrive0 b 254 0
    # chgrp floppy /dev/dexdrive0

At this point, you can use `/dev/dexdrive0` like you would any other (tiny)
block device.  That device will remain active for as long as dexattach is
running.

Up to four block devices can be active at the same time.


OTHER FEATURES
--------------

Two sysfs entries are created to provide the DexDrive model (PSX or N64) and
firmware revision:

    $ cat /sys/block/dexdrive0/model
    PSX
    $ cat /sys/block/dexdrive0/firmware_version
    1.12


COMPATIBILITY
-------------

This module is compatible with kernel versions 3.0 and up.

It supports both the PlayStation and Nintendo 64 DexDrive models, using any
compatible memory card.  No explicit support is provided for non-conventional
memory cards with larger capacity, but they will still work in that they
behave like a regular memory card.  (Page switching will have to be handled
manually, though.)


SOURCE
------

The complete source for this driver can be found on GitHub:

https://github.com/fbriere/linux-dexdrive


CONTACT
-------

Author:  Frédéric Brière - fbriere@fbriere.net

Please feel free to email me if you have any questions, bugs, patches, or
general comments on my sanity for writing this driver.  :smile:

