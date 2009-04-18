/*
    Utility to set the line discipline to the DexDrive block device driver
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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/select.h>

#include "dexdrive.h"


/* tty baud rate */
#define DEX_TTY_SPEED	B38400
/* Timeout (in msecs) when waiting for the device to reply */
#define DEX_TIMEOUT	200
/* Garbage data -- this is the default used by InterAct's DexPlorer */
#define DEX_GARBAGE	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
/* What we expect the device to reply */
#define DEX_REPLY	"IAI\x21"
/* Convenience macro returning the length in bytes of the previous reply */
#define DEX_REPLY_LEN	(sizeof(DEX_REPLY) - 1)


/*
 * Like read(), but blocks for timeout msecs on a non-blocking fd.
 * (Note that this currently doesn't handle EINTR.)
 */
ssize_t read_timeout(int fd, void *buf, ssize_t count, long timeout)
{
	fd_set set;
	struct timeval tv;
	void *buf_orig = buf;
	int tmp;

	FD_ZERO(&set);
	FD_SET(fd, &set);

	while (count > 0) {
		tv.tv_sec = timeout / 1000;
		tv.tv_usec = (timeout % 1000) * 1000;

		tmp = select(fd + 1, &set, NULL, NULL, &tv);
		if (tmp < 0)
			return -1;
		if (tmp == 0)
			break;	/* timeout */

		tmp = read(fd, buf, count);
		if (tmp < 0)
			return tmp;
		if (tmp == 0)
			break;	/* EOF */

		buf += tmp;
		count -= tmp;
	}

	return buf - buf_orig;
}

/*
 * Check whether there is a DexDrive connected to a tty.
 */
int dex_check(int fd)
{
	char buf[DEX_REPLY_LEN];
	int n;

	write(fd, DEX_GARBAGE, sizeof(DEX_GARBAGE) - 1);

	n = read_timeout(fd, buf, DEX_REPLY_LEN, DEX_TIMEOUT);
	if (n < 0)
		return -1;

	return (n == DEX_REPLY_LEN)
		&& (memcmp(buf, DEX_REPLY, DEX_REPLY_LEN) == 0);
}

/*
 * Set up a tty for communicating with a DexDrive, and set it to the dexdrive
 * line discipline, after making sure that there is a device connected.
 */
int dex_set_tty(int fd)
{
	struct termios term, old_term;
	int ldisc = DEX_LDISC;
	int errno_bak;

	if (tcgetattr(fd, &old_term) < 0)
		return -1;

	term = old_term;

	/* 8N1 with hardware flow control */
	term.c_cflag	&= ~(CSIZE | CSTOPB | PARENB);
	term.c_cflag	|= (CS8 | CREAD | CLOCAL | CRTSCTS);
	/*
	 * Apparently, it's not nice to initialize these fields directly.
	 * But since ppp does it, we'll use that as our excuse.
	 */
	term.c_iflag	= IGNBRK | IGNPAR;
	term.c_oflag	= 0;
	term.c_lflag	= 0;
	/* Are these of any use with O_NONBLOCK? */
	term.c_cc[VMIN]  = 0;
	term.c_cc[VTIME] = 1;

	cfsetospeed(&term, DEX_TTY_SPEED);
	cfsetispeed(&term, DEX_TTY_SPEED);

	if (tcflush(fd, TCIOFLUSH) < 0)
		return -1;

	/* Switch the tty to our own settings */
	if (tcsetattr(fd, TCSANOW, &term) < 0)
		goto err;

	/* Now that we can talk, check whether there's a device attached */
	switch (dex_check(fd)) {
	case 0:
		/* No error, but no device either, so let's fake something */
		errno = ENXIO;
	case -1:
		goto err;
	}
	
	/* Finally set the line discipline */
	if (ioctl(fd, TIOCSETD, &ldisc) < 0)
		goto err;

	return 0;

err:
	/* Make sure to preserve errno */
	errno_bak = errno;

	/* Restore the old tty settings */
	tcflush(fd, TCIOFLUSH);
	tcsetattr(fd, TCSANOW, &old_term);

	errno = errno_bak;
	return -1;
}

/* Print the block device number associated with a tty */
void print_dev(int fd)
{
	unsigned int major, minor;

	ioctl(fd, DEX_IOCTL_GET_MAJOR, &major);
	ioctl(fd, DEX_IOCTL_GET_MINOR, &minor);

	printf("Device number is %u:%u\n", major, minor);
}

int main(int argc, char **argv) {
	char *devname;
	int fd;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s devicename\n", argv[0]);
		return 1;
	}

	devname = argv[1];

        fd = open(devname, O_RDWR | O_NOCTTY | O_NONBLOCK);
	if (fd < 0) {
		fprintf(stderr, "Cannot open %s: %s\n",
					devname, strerror(errno));
		return 1;
	}

	/* Provide a more explicit error message for a common mistake */
	if (!isatty(fd)) {
		fprintf(stderr, "%s is not a serial line\n", devname);
		return 1;
	}

	if (dex_set_tty(fd) < 0) {
		perror("Cannot set line discipline");
		return 1;
	}

	print_dev(fd);

	pause();

	return 0;
}

