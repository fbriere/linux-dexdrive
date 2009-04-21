/*
    dexdrive.c: DexDrive block device driver for Linux
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


#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/kernel.h>
#include <linux/bitmap.h>
#include <linux/completion.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/slab.h>		/* kmalloc() */
#include <linux/string.h>	/* memcpy() */
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/sched.h>	/* linux/wait.h should include this one */

#include <linux/blkdev.h>
#include <linux/tty.h>
#include <linux/tty_ldisc.h>

#include "dexdrive.h"
#include "compat.h"


/*
 * The maximum message length is 261, during READ/WRITE for the N64 model:
 *   I A I <opcode> <256 bytes of data> <checksum>.
 * (Although PAGE replies can be much longer than this.)
 */
#define DEX_NAME	"dexdrive"	/* Driver name */
#define DEX_BUFSIZE	261		/* Size of input/output buffer */
#define DEX_TIMEOUT	100		/* Timeout in msecs when waiting */
#define DEX_MAX_RETRY	2		/* Maximum number of retries */
#define DEX_MAX_DEVICES	4		/* Maximum number of devices */


/* DexDrive models */
enum dex_model { DEX_MODEL_PSX, DEX_MODEL_N64 };

/* List of operations we perform with the device */
enum dex_command {
	DEX_CMD_NONE,
	DEX_CMD_READ,
	DEX_CMD_SEEK,
	DEX_CMD_WRITE,
	DEX_CMD_INIT,
	DEX_CMD_MAGIC,
	DEX_CMD_ON,
	DEX_CMD_OFF,
	DEX_CMD_STATUS,
	DEX_CMD_PAGE,	/* TODO: Not implemented yet */
};

/* List of opcodes */
enum dex_opcode {
	DEX_OPCODE_INIT		= 0x00,
	DEX_OPCODE_STATUS	= 0x01,
	DEX_OPCODE_READ		= 0x02,
	DEX_OPCODE_SEEK		= 0x03,
	DEX_OPCODE_WRITE	= 0x04,
	DEX_OPCODE_PAGE		= 0x05,
	DEX_OPCODE_LIGHT	= 0x07,
	DEX_OPCODE_MAGIC	= 0x27,

	DEX_OPCODE_POUT		= 0x20,
	DEX_OPCODE_ERROR	= 0x21,
	DEX_OPCODE_NOCARD	= 0x22,
	DEX_OPCODE_CARD		= 0x23,
	DEX_OPCODE_CARD_NEW	= 0x25,
	DEX_OPCODE_SEEK_OK	= 0x27,
	DEX_OPCODE_WOK		= 0x28,
	DEX_OPCODE_WSAME	= 0x29,
	DEX_OPCODE_WAIT		= 0x2a,
	DEX_OPCODE_ID		= 0x40,
	DEX_OPCODE_DATA		= 0x41,
};

/* Prefix sent with all commands/replies */
#define DEX_CMD_PREFIX	"IAI"

/* Default init string used by InterAct's software */
#define DEX_INIT_STR	"\x10\x29\x23\xbe\x84\xe1\x6c\xd6\xae\x52" \
				"\x90\x49\xf1\xf1\xbb\xe9\xeb"


static unsigned int major;
module_param(major, uint, 0);
MODULE_PARM_DESC(major, "Major device number (automatically assigned by default)");

/* This must be configurable until the day we get our own value */
static int ldisc = DEX_LDISC;
module_param(ldisc, int, 0);
MODULE_PARM_DESC(ldisc, "Line discipline number");


#define warn(msg, args...) \
	printk(KERN_WARNING DEX_NAME ": " msg "\n" , ## args)

#define PDEBUG(msg, args...) \
	printk(KERN_DEBUG DEX_NAME ": " msg "\n" , ## args)


/* Data associated with each device */
struct dex_device {
	int i;

	/* spinlock -- should be held almost all the time */
	spinlock_t lock;
	/* tty attached to the device */
	struct tty_struct *tty;
	/* number of open handles that point to this device */
	int open_count;
	/* current command, or nothing if we are free */
	enum dex_command command;
	/* sector number to read/write */
	int sector;
	/* where to fetch/store data */
	char *data;
	/* whether we have received and processed a reply */
	int got_reply;
	/* command is completed */
	struct completion command_done;
	/* return value of command */
	int command_return;
	/* input/output buffer */
	char buf[DEX_BUFSIZE];
	/* number of bytes read / to write */
	int count_in, count_out;
	/* pointer to the next byte to be written */
	char *ptr_out;

	/* model: PSX or N64 */
	enum dex_model model;
	/* Firmware version byte */
	unsigned char firmware_version;

	/* Disk device we have created */
	struct gendisk *gd;
	/* Dummy request queue -- which we don't use */
	struct request_queue *request_queue;
	/* Stack of block IO operations we need to perform */
	struct bio *bio_head, *bio_tail;
	/* Kernel thread responsible for dealing with the bio stack */
	struct task_struct *thread;
	/* Wait queue used to wake up the thread when filling the stack */
	wait_queue_head_t thread_wait;
};

/* This is just to remember which values are currently in use */
static DECLARE_BITMAP(dex_devices, DEX_MAX_DEVICES);
static DEFINE_MUTEX(dex_devices_mutex);

/* Find and set a free bit */
static int dex_get_i(void)
{
	int i;

	if (mutex_lock_interruptible(&dex_devices_mutex) < 0)
		return -ERESTARTSYS;

	i = find_first_zero_bit(dex_devices, DEX_MAX_DEVICES);

	if (i < DEX_MAX_DEVICES)
		set_bit(i, dex_devices);
	else
		i = -1;

	mutex_unlock(&dex_devices_mutex);

	return i;
}

static void dex_put_i(int i)
{
	/* We can't return -ERESTARTSYS, so just block */
	mutex_lock(&dex_devices_mutex);
	clear_bit(i, dex_devices);
	mutex_unlock(&dex_devices_mutex);
}

/*
 * Record that we are now using this device.  Returns the previous number
 * of open handles, or <0 in case of error.
 */
static int dex_get(struct dex_device *dex)
{
	unsigned long flags;
	int ret = 0;

	PDEBUG("> dex_get(%p)", dex);

	spin_lock_irqsave(&dex->lock, flags);

	if (dex->tty) {
		ret = dex->open_count++;
		/* Substract one for the tty */
		ret--;
	} else {
		ret = -ENXIO;
	}

	spin_unlock_irqrestore(&dex->lock, flags);

	PDEBUG("< dex_get := %d", ret);

	return ret;
}

/*
 * Record that we are no longer using this device.  If it is no longer used,
 * then it will be destroyed.  Returns the current number of open handles, or
 * <0 if the device was freed.
 */
static void dex_block_teardown(struct dex_device *dex);
static int dex_put(struct dex_device *dex)
{
	unsigned long flags;
	int tmp;

	PDEBUG("> dex_put(%p)", dex);

	spin_lock_irqsave(&dex->lock, flags);
	tmp = --dex->open_count;
	spin_unlock_irqrestore(&dex->lock, flags);

	if (tmp == 0) {
		dex_block_teardown(dex);
		dex_put_i(dex->i);
		kfree(dex);
	}

	/* Substract one for the tty */
	tmp--;

	PDEBUG("< dex_put := %i", tmp);

	return tmp;
}


/* Low-level functions */

/*
 * Split a 16-bit sector number into two bytes, for use as argument to
 * SEEK/READ/WRITE, and for computing the checksum on READ.
 */

static inline unsigned char lsb(int x)
{
	return x;
}

static inline unsigned char msb(int x)
{
	return (x >> 8);
}

/*
 * PSX sectors have 256 bytes; N64 sectors, 512
 */

static inline int dex_sector_shift(const struct dex_device *dex)
{
	return (dex->model == DEX_MODEL_PSX ? 7 : 8);
}

static inline int dex_sector_size(const struct dex_device *dex)
{
	return (1 << dex_sector_shift(dex));
}

/*
 * Reverse the bits in a byte, copied from
 * <http://graphics.stanford.edu/~seander/bithacks.html#ReverseByteWith32Bits>.
 */
static inline unsigned char reverse_byte(unsigned char b)
{
	return ((b * 0x0802LU & 0x22110LU) | (b * 0x8020LU & 0x88440LU))
		* 0x10101LU >> 16;
}

static inline unsigned char dex_checksum(const unsigned char *ptr, int len)
{
	unsigned char res = 0;
	int i;

	for (i = 0; i < len; i++)
		res ^= ptr[i];

	return res;
}

/* Add a character to dex->buf[] */
static inline void add2bufc(struct dex_device *dex, char c)
{
	dex->buf[dex->count_out++] = c;
}

/* Add a string to dex->buf[] */
static inline void add2bufs(struct dex_device *dex, const char *str, int len)
{
	memcpy(dex->buf + dex->count_out, str, len);
	dex->count_out += len;
}


/*
 * Fills dex->buf[] with the data that will be sent to the device.  Returns <0
 * in case of error.
 */
static int dex_prepare_cmd(struct dex_device *dex)
{
	PDEBUG("> dex_prepare_cmd(%p)", dex);

	dex->count_out = 0;

	add2bufs(dex, DEX_CMD_PREFIX, sizeof(DEX_CMD_PREFIX)-1);

	switch (dex->command) {
	case DEX_CMD_READ:
		add2bufc(dex, DEX_OPCODE_READ);
		add2bufc(dex, lsb(dex->sector));
		add2bufc(dex, msb(dex->sector));
		break;
	case DEX_CMD_SEEK:
		if (dex->model == DEX_MODEL_PSX)
			return -1;

		add2bufc(dex, DEX_OPCODE_SEEK);
		add2bufc(dex, lsb(dex->sector));
		add2bufc(dex, msb(dex->sector));
		break;
	case DEX_CMD_WRITE:
		add2bufc(dex, DEX_OPCODE_WRITE);
		if (dex->model == DEX_MODEL_PSX) {
			add2bufc(dex, msb(dex->sector));
			add2bufc(dex, lsb(dex->sector));
			add2bufc(dex, reverse_byte(msb(dex->sector)));
			add2bufc(dex, reverse_byte(lsb(dex->sector)));
		}
		add2bufs(dex, dex->data, dex_sector_size(dex));
		add2bufc(dex, dex_checksum((dex->buf + 4), (dex->count_out - 4)));
		break;
	case DEX_CMD_INIT:
		add2bufc(dex, DEX_OPCODE_INIT);
		add2bufs(dex, DEX_INIT_STR, sizeof(DEX_INIT_STR)-1);
		break;
	case DEX_CMD_MAGIC:
		add2bufc(dex, DEX_OPCODE_MAGIC);
		break;
	case DEX_CMD_ON:
		add2bufc(dex, DEX_OPCODE_LIGHT);
		add2bufc(dex, 1);
		break;
	case DEX_CMD_OFF:
		add2bufc(dex, DEX_OPCODE_LIGHT);
		add2bufc(dex, 0);
		break;
	case DEX_CMD_STATUS:
		add2bufc(dex, DEX_OPCODE_STATUS);
		break;
	default:
		warn("Unknown command: %d", dex->command);
		return -1;
	}

	PDEBUG("< dex_prepare_cmd");

	return 0;
}

/*
 * Processes what has already been received in dex->buf[].  Returns >0 if the
 * response has been processed, 0 if is currently incomplete, and <0 if there
 * was an error.
 */
#define mkpair(req, reply) (((req) << 8) | (reply))
static int dex_read_cmd(struct dex_device *dex)
{
	int reply = dex->buf[3];
	int n_args = dex->count_in - 4;

	PDEBUG("> dex_read_cmd(%p) [ reply:%i n_args:%i ]", dex, reply, n_args);

	if (dex->count_in < 4)
		return(0);

	/* There should be a better way to do this... */
	if ((dex->command == DEX_CMD_ON) || (dex->command == DEX_CMD_OFF)) {
		PDEBUG("faking NOCARD for CMD_LIGHT");
		reply = DEX_OPCODE_NOCARD;
	}

	if (dex->command == DEX_CMD_MAGIC) {
		PDEBUG("faking NOCARD for CMD_MAGIC");
		reply = DEX_OPCODE_NOCARD;
	}

	if (reply == DEX_OPCODE_ERROR) {
		PDEBUG("got CMD_ERROR");
		return -EIO;
	}

	if (reply == DEX_OPCODE_POUT) {
		PDEBUG("got CMD_POUT");
		return -EIO;
	}

	switch (mkpair(dex->command, reply)) {
	case mkpair(DEX_CMD_READ, DEX_OPCODE_DATA):
		if (n_args < (dex_sector_size(dex) + 1))
			return 0;
		if ((dex_checksum((dex->buf + 4), (dex_sector_size(dex) + 1))
			^ lsb(dex->sector) ^ msb(dex->sector)) != 0) {
			return -EIO;
		}
		memcpy(dex->data, (dex->buf + 4), dex_sector_size(dex));
		return 1;
	case mkpair(DEX_CMD_SEEK, DEX_OPCODE_SEEK_OK):
	case mkpair(DEX_CMD_WRITE, DEX_OPCODE_WOK):
	case mkpair(DEX_CMD_WRITE, DEX_OPCODE_WSAME):
		return 1;
	case mkpair(DEX_CMD_READ, DEX_OPCODE_NOCARD):
	case mkpair(DEX_CMD_SEEK, DEX_OPCODE_NOCARD):
	case mkpair(DEX_CMD_WRITE, DEX_OPCODE_NOCARD):
		return -EIO;
	case mkpair(DEX_CMD_INIT, DEX_OPCODE_ID):
		if (n_args < 5) return 0;
		memcpy(dex->data, (dex->buf + 4), 5);
		return 1;
	case mkpair(DEX_CMD_MAGIC, DEX_OPCODE_NOCARD):
	case mkpair(DEX_CMD_ON, DEX_OPCODE_NOCARD):
	case mkpair(DEX_CMD_OFF, DEX_OPCODE_NOCARD):
		return 1;
	case mkpair(DEX_CMD_STATUS, DEX_OPCODE_NOCARD):
		return -ENXIO;
	case mkpair(DEX_CMD_STATUS, DEX_OPCODE_CARD):
	case mkpair(DEX_CMD_STATUS, DEX_OPCODE_CARD_NEW):
		if ((dex->model == DEX_MODEL_PSX) && (n_args < 1))
			return 0;
		return 1;
	default:
		PDEBUG("got unknown reply %i from device", reply);
		return -EIO;
	}

	PDEBUG("< dex_read_cmd");
}
#undef mkpair

/*
 * Perform one attempt at sending a command, and wait for the reply.
 */
static void dex_tty_write(struct dex_device *dex);
static int dex_attempt_cmd(struct dex_device *dex, unsigned long *flags)
{
	int tmp;

	PDEBUG("> dex_attempt_cmd(%p, %p)", dex, flags);

	if (!dex->tty)
		return -EIO;

	if (dex_prepare_cmd(dex) < 0)
		return -EIO;

	dex->ptr_out = dex->buf;
	dex_tty_write(dex);

	dex->count_in = 0;
	dex->got_reply = 0;

	/* Default in case of timeout */
	dex->command_return = -EIO;

	/* The N64 model might not reply to these, but we don't mind */
	if (dex->model == DEX_MODEL_N64) {
		switch (dex->command) {
		case DEX_CMD_MAGIC:
		case DEX_CMD_ON:
		case DEX_CMD_OFF:
			dex->command_return = 0;
		/* Silence gcc warning about not checking the other enum values */
		default:
			;
		}
	}

	init_completion(&dex->command_done);
	spin_unlock_irqrestore(&dex->lock, *flags);

	/* TODO: Skip this for N64 and DEX_CMD_ON/OFF */

	tmp = wait_for_completion_interruptible_timeout(&dex->command_done,
						msecs_to_jiffies(DEX_TIMEOUT));
	/* Throw -ERESTARTSYS if needed */
	if (tmp < 0)
		return tmp;

	spin_lock_irqsave(&dex->lock, *flags);

	PDEBUG("< dex_attempt_cmd := %i", dex->command_return);

	return dex->command_return;
}


/* High-level functions */

/*
 * Check if we have received a complete response, and process it if this is
 * the case.
 */
static void dex_check_reply(struct dex_device *dex)
{
	unsigned long flags;
	int ret;

	PDEBUG("> dex_check_reply(%p)", dex);

	spin_lock_irqsave(&dex->lock, flags);

	if (! dex->got_reply) {
		ret = dex_read_cmd(dex);
		PDEBUG(" got %i", ret);
		if (ret != 0) {
			dex->got_reply = 1;
			dex->command_return = ret < 0 ? ret : 0;
			complete(&dex->command_done);
		}
	}

	spin_unlock_irqrestore(&dex->lock, flags);

	PDEBUG("< dex_check_reply");
}

/*
 * Send a command to the device and wait until the response has been
 * processed.  Returns <0 in case of an error.
 *
 * The meaning of n and *ptr are specific to each command:
 *
 *   - For DEX_CMD_SEEK (N64) and DEX_CMD_READ/WRITE (PSX), n contains the
 *     sector number.
 *   - For DEX_CMD_READ/WRITE (both models), the sector data will be read
 *     from or written to *ptr.
 *   - For DEX_CMD_INIT, the 5-byte ID reply will be stored in *ptr.
 *
 * Otherwise, these arguments are not used.
 */
static int dex_do_cmd(struct dex_device *dex, int cmd, int n, void *ptr)
{
	unsigned long flags;
	int ret, i;

	PDEBUG("> dex_do_cmd(%p, %d", dex, cmd);

	spin_lock_irqsave(&dex->lock, flags);

	if (dex->command != DEX_CMD_NONE) {
		warn("Already busy doing %i", dex->command);
		ret = -EBUSY;
		goto out;
	}

	dex->command = cmd;
	dex->sector = n;
	dex->data = ptr;

	for (i = 0; i <= DEX_MAX_RETRY; i++) {
		PDEBUG(" Attempt #%i", i);
		ret = dex_attempt_cmd(dex, &flags);
		PDEBUG(" Result: %i", ret);
		if (ret == 0)
			break;
	}

out:
	dex->command = DEX_CMD_NONE;

	spin_unlock_irqrestore(&dex->lock, flags);

	PDEBUG("< dex_do_cmd := %i", ret);

	return ret;
}

/*
 * Read/write a number of consecutive sectors from/to the device.  Returns <0
 * in case of an error.
 */
static int dex_transfer(struct dex_device *dex,
			unsigned int sector, unsigned int len,
			char *buffer, int write)
{
	int error = 0;

	PDEBUG("> dex_transfer(%p, %u, %u, %p, %i", dex, sector, len,
					buffer, write);

	for (; len > 0; sector++, len--) {
		if (write && (dex->model == DEX_MODEL_N64)) {
			error = dex_do_cmd(dex, DEX_CMD_SEEK, sector, NULL);
			if (error < 0)
				break;
		}

		error = dex_do_cmd(dex,
					(write ? DEX_CMD_WRITE : DEX_CMD_READ),
					sector, buffer);

		if (error < 0)
			break;

		buffer += dex_sector_size(dex);
	}

	PDEBUG("< dex_transfer := %i", error);

	return error;
}

/*
 * Initialize the device.  This should not be called in parallel with
 * any other communication.  Returns -ENXIO if no card is inserted.
 */
static int dex_spin_up(struct dex_device *dex)
{
	char init_data[5];
	int ret;

	PDEBUG("> dex_spin_up(%p)", dex);

	ret = dex_do_cmd(dex, DEX_CMD_INIT, 0, init_data);
	if (ret < 0)
		return ret;

	if (init_data[1] == 'P' && init_data[2] == 'S' && init_data[3] == 'X')
		dex->model = DEX_MODEL_PSX;
	else if (init_data[1] == 'N' && init_data[2] == '6' && init_data[3] == '4')
		dex->model = DEX_MODEL_N64;
	else
		return -EIO;

	PDEBUG(" model is %i", dex->model);

	/* A regular PSX memory card holds 128 KiB; a N64 card holds 32 KiB */
	set_capacity(dex->gd, (dex->model == DEX_MODEL_PSX ? 128 : 32) * 2);

	dex->firmware_version = init_data[4];

	ret = dex_do_cmd(dex, DEX_CMD_MAGIC, 0, NULL);
	if (ret < 0)
		return ret;

	ret = dex_do_cmd(dex, DEX_CMD_STATUS, 0, NULL);
	if (ret < 0)
		return ret;

	PDEBUG("< dex_spin_up := %i", ret);

	/* Don't bother turning on the light if no card is present */
	if (ret == 0)
		dex_do_cmd(dex, DEX_CMD_ON, 0, NULL);

	return ret;
}

/*
 * Turn off the device.  All this currently does is turn off the light.
 */
static void dex_spin_down(struct dex_device *dex)
{
	dex_do_cmd(dex, DEX_CMD_OFF, 0, NULL);
}


/* sysfs functions */

/*
 * Helper function for dex_show_firmware_version().  Returns the n
 * consecutive bits in word, starting with lowest.
 */
static inline unsigned int extract_bits(unsigned int word,
					unsigned int lowest, unsigned int n)
{
	return (word >> lowest) & ((1 << n) - 1);
}

static ssize_t dex_show_model(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct dex_device *dex = dev_to_disk(dev)->private_data;

	if (dex->tty) {
		return snprintf(buf, 5, "%s\n",
				(dex->model == DEX_MODEL_PSX ? "PSX" : "N64"));
	} else {
		return -ENODEV;
	}
}

static ssize_t dex_show_firmware_version(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct dex_device *dex = dev_to_disk(dev)->private_data;

	if (dex->tty) {
		/* Version x.yz is encoded as xxyyyyzz */
		return snprintf(buf, 7, "%d.%d%d\n",
				extract_bits(dex->firmware_version, 6, 2),
				extract_bits(dex->firmware_version, 2, 4),
				extract_bits(dex->firmware_version, 0, 2));
	} else {
		return -ENODEV;
	}
}

static DEVICE_ATTR(model, S_IRUGO, dex_show_model, NULL);
static DEVICE_ATTR(firmware_version, S_IRUGO, dex_show_firmware_version, NULL);


/* Block device functions */

/*
 * Handle a pending block IO operation.
 */
static inline void dex_block_do_bio(struct dex_device *dex, struct bio *bio)
{
	sector_t sector;
	struct bio_vec *bvec;
	int i;
	int error = 0;

	PDEBUG(">> dex_block_do_bio(%p, %p)", dex, bio);

	sector = bio->bi_sector << (9 - dex_sector_shift(dex));

	bio_for_each_segment(bvec, bio, i) {
		sector_t len = (bvec->bv_len >> dex_sector_shift(dex));

		error = dex_transfer(dex, sector, len,
					kmap(bvec->bv_page) + bvec->bv_offset,
					bio_data_dir(bio) == WRITE);

		if (error < 0)
			break;

		sector += len;
	}

	bio_endio(bio, error);

	PDEBUG("<< dex_block_do_bio");
}

/*
 * Add a bio to the queue -- must be called while holding the spinlock.
 */
static void dex_block_add_bio(struct dex_device *dex, struct bio *bio)
{
	if (dex->bio_tail)
		dex->bio_tail->bi_next = bio;
        else
		dex->bio_head = bio;

	dex->bio_tail = bio;
}

/*
 * Remove a bio from the queue -- must be called while holding the spinlock.
 */
static struct bio *dex_block_get_bio(struct dex_device *dex)
{
	struct bio *bio;

	if ((bio = dex->bio_head)) {
		if (bio == dex->bio_tail)
			dex->bio_tail = NULL;
		dex->bio_head = bio->bi_next;
		bio->bi_next = NULL;
	}

	return bio;
}

/*
 * Called by the kernel when a new block IO operation is created, which we
 * add to the queue for dex_block_thread() to handle.
 */
static int dex_block_make_request(struct request_queue *queue, struct bio *bio)
{
	struct dex_device *dex = queue->queuedata;
	unsigned long flags;

	PDEBUG("> dex_block_make_request(%p, %p)", queue, bio);

	if (!dex) {
		/* We are shutting down -- drop everything on the floor */
		bio_io_error(bio);
		return 0;
	}

	spin_lock_irqsave(&dex->lock, flags);
	dex_block_add_bio(dex, bio);
	wake_up(&dex->thread_wait);
	spin_unlock_irqrestore(&dex->lock, flags);

	PDEBUG("< dex_block_make_request");

	return 0;
}

/*
 * A kernel thread dedicated to processing bio's; it merely waits for more to
 * appear on the stack, and dispatches them to dex_block_do_bio().
 */
static int dex_block_thread(void *data)
{
	struct dex_device *dex = data;
	struct bio *bio;
	unsigned long flags;

	PDEBUG(">> dex_block_thread starting");

	/* set_user_nice(current, -20); */

	while (!kthread_should_stop() || dex->bio_head) {
		wait_event(dex->thread_wait,
				dex->bio_head || kthread_should_stop());

		if (! dex->bio_head)
			continue;

		spin_lock_irqsave(&dex->lock, flags);
		bio = dex_block_get_bio(dex);
		spin_unlock_irqrestore(&dex->lock, flags);

		dex_block_do_bio(dex, bio);
	}

	PDEBUG("<< dex_block_thread exiting");

	return 0;
}

/*
 * Mutex to prevent conflict between multiple open()/release().  We may end
 * up freeing dex when calling dex_put(), so a global mutex is safer (well,
 * easier) than storing it within dex_device.  Unfortunately, it does mean
 * that calls to distinct devices will block each other, but does anybody
 * care?
 */
DECLARE_MUTEX(open_release_mutex);

/*
 * Called when our block device is opened.
 */
static int dex_block_open(COMPAT_OPEN_PARAMS)
{
	struct dex_device *dex;
	int ret;

	PDEBUG("> dex_block_open(...)");

	if (down_interruptible(&open_release_mutex))
		return -ERESTARTSYS;

	dex = compat_open_get_disk()->private_data;

	ret = dex_get(dex);

	/* Initialize the device if we are the first to open it */
	if (ret == 0) {
		/* FIXME: Wait for dex_block_thread to empty its queue */
		ret = dex_spin_up(dex);
		if (ret < 0)
			goto out;

		check_disk_change(compat_open_get_bdev());

		/* Now we create our sysfs files */

		ret = device_create_file(disk_to_dev(dex->gd),
						&dev_attr_model);
		if (ret < 0)
			goto out;

		ret = device_create_file(disk_to_dev(dex->gd),
						&dev_attr_firmware_version);
		if (ret < 0)
			goto out;
	}

out:
	if (ret < 0)
		dex_put(dex);

	up(&open_release_mutex);

	PDEBUG("< dex_block_open := %d", ret);

	return ret;
}

/*
 * Called when our block device is closed.
 */
static int dex_block_release(COMPAT_RELEASE_PARAMS)
{
	struct dex_device *dex;

	PDEBUG("> dex_block_release(...)");

	if (down_interruptible(&open_release_mutex))
		return -ERESTARTSYS;

	dex = compat_release_get_disk()->private_data;

	/* FIXME: Yuck */
	if (dex->tty && dex->open_count == 2) {
		device_remove_file(disk_to_dev(dex->gd),
						&dev_attr_model);
		device_remove_file(disk_to_dev(dex->gd),
						&dev_attr_firmware_version);
		dex_spin_down(dex);
	}

	dex_put(dex);

	up(&open_release_mutex);

	PDEBUG("< dex_block_release := %d", 0);
	return 0;
}

/*
 * Called by our own call to check_disk_change() in dex_block_open().
 *
 * It is somewhat unclear what we should do in our case, where we have a
 * removable media, but cannot tell if it has been changed.  The safest
 * option is probably to always return true, which is what we do.  And
 * since check_disk_change() only checks for true/false, we symbolically
 * return an error value.
 */
static int dex_block_media_changed(struct gendisk *gd)
{
	return -EINVAL;
}

static struct block_device_operations dex_bdops = {
	.owner			= THIS_MODULE,
	.open			= dex_block_open,
	.release		= dex_block_release,
	.media_changed		= dex_block_media_changed,
};

/*
 * Set up the block device half of the dex_device structure.
 */
static int dex_block_setup(struct dex_device *dex)
{
	int ret;

	dex->request_queue = blk_alloc_queue(GFP_KERNEL);
	if (!dex->request_queue)
		return -ENOMEM;

	blk_queue_hardsect_size(dex->request_queue, 512);

	dex->request_queue->queuedata = dex;
	blk_queue_make_request(dex->request_queue, dex_block_make_request);

	/*
	 * Turn off readahead, which doesn't do us much good.  (The default
	 * value is 256 sectors, which basically gobbles up the whole card
	 * on any read operation.)  A small value might be useful, but the
	 * unit is PAGE_CACHE_SIZE (4 KiB or more), which is still too big
	 * for our purposes.
	 */
	dex->request_queue->backing_dev_info.ra_pages = 0;

	dex->bio_head = dex->bio_tail = NULL;

	init_waitqueue_head(&dex->thread_wait);
	dex->thread = kthread_run(dex_block_thread, dex, "dexdrive%d", dex->i);

	if (IS_ERR(dex->thread)) {
		warn("cannot create thread");
		ret = PTR_ERR(dex->thread);
		goto err;
	}

	dex->gd = alloc_disk(1);
	if (! dex->gd) {
		warn("cannot allocate gendisk struct");
		ret = -ENOMEM;
		goto err;
	}
	dex->gd->major = major;
	dex->gd->first_minor = dex->i;
	dex->gd->fops = &dex_bdops;
	dex->gd->queue = dex->request_queue;
	dex->gd->flags |= GENHD_FL_REMOVABLE;
	dex->gd->private_data = dex;
	snprintf(dex->gd->disk_name, 32, "dexdrive%u", dex->i);
	add_disk(dex->gd);

	return 0;

err:
	if (!IS_ERR(dex->thread))
		kthread_stop(dex->thread);

	if (dex->request_queue)
		blk_cleanup_queue(dex->request_queue);

	return ret;
}

/*
 * Tear down the block device half of the dex_device structure.
 */
static void dex_block_teardown(struct dex_device *dex)
{
	unsigned long flags;

	PDEBUG("> dex_block_teardown(%p)", dex);

	/* These may have been left behind */
	device_remove_file(disk_to_dev(dex->gd), &dev_attr_model);
	device_remove_file(disk_to_dev(dex->gd), &dev_attr_firmware_version);

	del_gendisk(dex->gd);

	/* Tell dex_block_make_request() to refuse any new bio's */
	spin_lock_irqsave(&dex->lock, flags);
	dex->request_queue->queuedata = NULL;
	spin_unlock_irqrestore(&dex->lock, flags);

	kthread_stop(dex->thread);

	put_disk(dex->gd);

	if (dex->request_queue)
		blk_cleanup_queue(dex->request_queue);

	PDEBUG("< dex_block_teardown");
}


/* tty functions */

/*
 * Send as much of our buffer as possible to the tty driver.  This should be
 * called while holding the spinlock.
 */
static void dex_tty_write(struct dex_device *dex)
{
	int i;

	/* dex->tty should always be defined here, but better safe than sorry */
	if (dex->tty && dex->count_out > 0) {
		PDEBUG("writing %d bytes to device", dex->count_out);

		i = (compat_tty_write(dex->tty))(dex->tty, dex->ptr_out,
							dex->count_out);
		dex->ptr_out += i;
		dex->count_out -= i;

		PDEBUG("(%d bytes were written)", i);

		if (dex->count_out > 0)
			set_bit(TTY_DO_WRITE_WAKEUP, &dex->tty->flags);
		else
			clear_bit(TTY_DO_WRITE_WAKEUP, &dex->tty->flags);
	}
}

/* Called by the tty driver when data is coming in */
static void dex_tty_receive_buf(struct tty_struct *tty,
				const unsigned char *buf, char *fp, int count)
{
	struct dex_device *dex = tty->disc_data;
	unsigned long flags;

	PDEBUG("> dex_tty_receive_buf(%p, %p, %p, %u)", tty, buf, fp, count);

	spin_lock_irqsave(&dex->lock, flags);

	if (dex->count_out > 0) {
		warn("Ignoring received data while we're still sending");
		goto out;
	}

	if (count > DEX_BUFSIZE - dex->count_in) {
		warn("Input buffer overflowing");
		count = DEX_BUFSIZE - dex->count_in;
	}
	memcpy(dex->buf + dex->count_in, buf, count);
	dex->count_in += count;

out:
	spin_unlock_irqrestore(&dex->lock, flags);

	dex_check_reply(dex);

	PDEBUG("< dex_tty_receive_buf");
}

/* Called by the tty driver when there's room for sending more data */
static void dex_tty_write_wakeup(struct tty_struct *tty)
{
	struct dex_device *dex = tty->disc_data;
	unsigned long flags;

	PDEBUG("> dex_tty_write_wakeup(%p)", tty);

	spin_lock_irqsave(&dex->lock, flags);
	dex_tty_write(dex);
	spin_unlock_irqrestore(&dex->lock, flags);

	PDEBUG("< dex_tty_write_wakeup");
}

/* Called by the tty driver upon ioctl() */
static int dex_tty_ioctl(struct tty_struct *tty, struct file *file,
				unsigned int cmd, unsigned long arg)
{
	struct dex_device *dex = tty->disc_data;
	unsigned long flags;
	int ret;

	PDEBUG("> dex_tty_ioctl(%p, %p, 0x%8x, %lu)", tty, file, cmd, arg);

	spin_lock_irqsave(&dex->lock, flags);

	switch (cmd) {
	case DEX_IOCTL_GET_MAJOR:
		ret = put_user(major, (unsigned int __user *)arg);
		break;
	case DEX_IOCTL_GET_MINOR:
		ret = put_user(dex->i, (unsigned int __user *)arg);
		break;
	default:
		ret = -ENOIOCTLCMD;
	}

	spin_unlock_irqrestore(&dex->lock, flags);

	PDEBUG("< dex_tty_ioctl := %d", ret);

	return ret;
}

/*
 * Called by the tty driver when associating a tty with our line discipline.
 * We create and setup a new dex_device.
 */
static int dex_tty_open(struct tty_struct *tty)
{
	struct dex_device *dex;
	int ret, i;

	PDEBUG("> dex_tty_open(%p)", tty);

	i = dex_get_i();
	if (i < 0)
		return -ENOMEM;

	PDEBUG(" got index %i", i);

	if ((dex = kmalloc(sizeof(struct dex_device), GFP_KERNEL)) == NULL) {
		warn("cannot allocate device struct");
		return -ENOMEM;
	}

	spin_lock_init(&dex->lock);
	dex->i = i;

	dex->tty = tty;
	dex->open_count = 1;
	dex->command = DEX_CMD_NONE;

	tty->disc_data = dex;
	tty->receive_room = DEX_BUFSIZE;

	if ((ret = dex_block_setup(dex)) < 0) {
		kfree(dex);
		return ret;
	}

	PDEBUG("< dex_tty_open := %d", 0);
	return 0;
}

/*
 * Called by the tty driver when our line discipline is torn down.
 */
static void dex_tty_close(struct tty_struct *tty)
{
	struct dex_device *dex = tty->disc_data;
	unsigned long flags;

	PDEBUG("> dex_tty_close(%p)", tty);

	spin_lock_irqsave(&dex->lock, flags);
	dex->tty = NULL;
	tty->disc_data = NULL;
	spin_unlock_irqrestore(&dex->lock, flags);

	dex_put(dex);

	PDEBUG("< dex_tty_close");
}

static struct tty_ldisc_ops dex_ldisc_ops = {
	.magic		= TTY_LDISC_MAGIC,
	.owner		= THIS_MODULE,
	.name		= DEX_NAME,
	.open		= dex_tty_open,
	.close		= dex_tty_close,
	.ioctl		= dex_tty_ioctl,
	.receive_buf	= dex_tty_receive_buf,
	.write_wakeup	= dex_tty_write_wakeup,
};


/* Module functions */

static void dex_cleanup(void)
{
	PDEBUG("> dex_cleanup()");
	if (tty_register_ldisc(ldisc, NULL) != 0)
		warn("can't unregister ldisc");
	unregister_blkdev(major, DEX_NAME);
	PDEBUG("< dex_cleanup");
}

static int __init dex_init(void)
{
	int tmp;

	PDEBUG("> dex_init()");
	if ((tmp = register_blkdev(major, DEX_NAME)) < 0) {
		warn("can't get major %d", major);
		return tmp;
	}
	if (major == 0)
		major = tmp;
	PDEBUG("setting major to %d", major);

	if (tty_register_ldisc(ldisc, &dex_ldisc_ops) != 0) {
		warn("can't set ldisc");
		dex_cleanup();
		return -1;
	}

	PDEBUG("< dex_init := %d", 0);
	return 0;
}



module_init(dex_init);
module_exit(dex_cleanup);


/* Apparently, the kernel is not ready for UTF-8 yet */
MODULE_AUTHOR("Frederic Briere <fbriere@fbriere.net>");
MODULE_DESCRIPTION("DexDrive block device driver");
MODULE_LICENSE("GPL");

