/*
    dexdrive.h: DexDrive block device driver for Linux
    Copyright (C) 2002,2009  Frédéric Brière

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#ifndef _DEXDRIVE_H_
#define _DEXDRIVE_H_

#include <linux/ioctl.h>

/*
 * This defines a series of ioctl() requests specific to this driver.
 */

/*
 * "type" field of all ioctl() request numbers -- we grab the 80-9F range,
 * which is listed as free in Documentation/ioctl-number.txt .
 */
#define DEX_IOC_MAGIC	0xDD

/*
 * These can be called on the underlying tty device to obtain the device number
 * of the block device that was created.
 */
#define DEX_IOCTL_GET_MAJOR	_IOR(DEX_IOC_MAGIC, 0x81, unsigned int)
#define DEX_IOCTL_GET_MINOR	_IOR(DEX_IOC_MAGIC, 0x82, unsigned int)


#endif /* _DEXDRIVE_H */
