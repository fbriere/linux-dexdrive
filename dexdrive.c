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
#include <linux/init.h>

#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/slab.h>		/* kmalloc() */
#include <linux/string.h>	/* memcpy() */
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/sched.h>	/* linux/wait.h should include this one */

#include <linux/blkdev.h>
#include <linux/tty.h>
#include <linux/tty_ldisc.h>


#define DEX_NAME  "dexdrive"
#define DEX_MAJOR 251
#define DEX_LDISC N_X25  // Find one in include/linux/tty.h
#define DEX_BUFSIZE_OUT 1024 // Maximum is 137
#define DEX_BUFSIZE_IN 1024 // Maximum is 208
#define DEX_TIMEOUT 100 // in msecs
#define DEX_TIMEOUTJ (DEX_TIMEOUT * HZ / 1000)
#define DEX_IOC_MAGIC 0xfb

enum {
	DEX_REQ_NONE,
	DEX_REQ_READ,
	DEX_REQ_WRITE,
	DEX_REQ_INIT,
	DEX_REQ_MAGIC,
	DEX_REQ_ON,
	DEX_REQ_OFF,
	DEX_REQ_STATUS,
	DEX_REQ_PAGE	// Not implemented yet
};

#define DEX_CMD_INIT	'\x00'
#define DEX_CMD_STATUS	'\x01'
#define DEX_CMD_READ	'\x02'
#define DEX_CMD_WRITE	'\x04'
#define DEX_CMD_PAGE	'\x05'
#define DEX_CMD_LIGHT	'\x07'
#define DEX_CMD_POUT	'\x20'
#define DEX_CMD_ERROR	'\x21'
#define DEX_CMD_OK	'\x22'
#define DEX_CMD_OKCARD	'\x23'
#define DEX_CMD_MAGIC	'\x27'
#define DEX_CMD_WOK	'\x28'
#define DEX_CMD_WSAME	'\x29'
#define DEX_CMD_WAIT	'\x2a'
#define DEX_CMD_ID	'\x40'
#define DEX_CMD_DATA	'\x41'

#define DEX_CMD_PREFIX	"IAI"

#define DEX_INIT_STR	"\x10\x29\x23\xbe\x84\xe1\x6c\xd6\xae\x52" \
				"\x90\x49\xf1\xf1\xbb\xe9\xeb"

/*
#define DEX_IOCGMAJOR	_IOR(DEX_IOC_MAGIC, 1, sizeof(int))
#define DEX_IOCGMINOR	_IOR(DEX_IOC_MAGIC, 2, sizeof(int))
#define DEX_IOCSMINOR	_IOW(DEX_IOC_MAGIC, 3, sizeof(int))
*/

static unsigned int major = DEX_MAJOR;

#define warn(msg, args...) \
	printk(KERN_WARNING DEX_NAME ": " msg "\n" , ## args)

#define PDEBUG(msg, args...) \
	printk(KERN_DEBUG DEX_NAME ": " msg "\n" , ## args)

#define add2bufc(c) \
	do { dex->buf_out[dex->count_out] = c; dex->count_out++; } while(0)

#define add2bufs(s,n) \
	do { memcpy(dex->buf_out + dex->count_out, s, n); \
			dex->count_out += n; } while(0)

#define lsb(x) ((x) & 0xff)
#define msb(x) (((x) >> 8) & 0xff)

/* Data associated with each device */
struct dex_device {
	/* spinlock -- should be held almost all the time */
	spinlock_t lock;
	/* tty attached to the device */
	struct tty_struct *tty;
	/* number of open handles that point to this device */
	int open_count;
	/* type of request, or nothing if we are free */
	int request;
	/* arguments provided with the request */
	int request_n;
	void *request_ptr;
	/* wait queue to wake up when request is completed */
	wait_queue_head_t request_wait;
	/* return value of request */
	int request_return;
	/* input and output buffers */
	char buf_in[DEX_BUFSIZE_IN], buf_out[DEX_BUFSIZE_OUT];
	/* number of bytes read / to write */
	int count_in, count_out;
	/* pointer to the next byte to be written */
	char *ptr_out;
	int media_present;
	int media_change;
	int minor;
	struct gendisk *gd;
	struct request_queue *request_queue;

	struct bio		*bio_head;
	struct bio		*bio_tail;

	struct task_struct	*thread;
	wait_queue_head_t	thread_wait;
};


/* Helper functions */

static inline int reverse_int (int x)
{
	int i, res = 0;
	for (i = 0; i < 4; i++) {
		res |= ((x & (1 << i)) << (7 - (2 * i)));
		res |= ((x & (1 << (7 - i))) >> (7 - (2 * i)));
	}
	return res;
}

static inline char dex_checksum (char *ptr, int len)
{
	char res = 0;
	int i;

	for (i = 0; i < len; i++)
		res ^= ptr[i];

	return res;
}


/* Data transfer */

static void dex_tty_write (struct dex_device *dex);
static void dex_write_cmd (struct dex_device *dex)
{
	PDEBUG("> dex_write_cmd(%p)", dex);

	dex->count_out = dex->count_in = 0;
	add2bufs(DEX_CMD_PREFIX, sizeof(DEX_CMD_PREFIX)-1);
	switch (dex->request) {
		case DEX_REQ_READ:
			add2bufc(DEX_CMD_READ);
			add2bufc(lsb(dex->request_n));
			add2bufc(msb(dex->request_n));
			break;
		case DEX_REQ_WRITE:
			add2bufc(DEX_CMD_WRITE);
			add2bufc(msb(dex->request_n));
			add2bufc(lsb(dex->request_n));
			add2bufc(reverse_int(msb(dex->request_n)));
			add2bufc(reverse_int(lsb(dex->request_n)));
			add2bufs(dex->request_ptr, 128);
			add2bufc(dex_checksum((dex->buf_out + 4), 132));
			break;
		case DEX_REQ_INIT:
			add2bufc(DEX_CMD_INIT);
			add2bufs(DEX_INIT_STR, sizeof(DEX_INIT_STR)-1);
			break;
		case DEX_REQ_MAGIC:
			add2bufc(DEX_CMD_MAGIC);
			break;
		case DEX_REQ_ON:
			add2bufc(DEX_CMD_LIGHT);
			add2bufc(1);
			break;
		case DEX_REQ_OFF:
			add2bufc(DEX_CMD_LIGHT);
			add2bufc(0);
			break;
		case DEX_REQ_STATUS:
			add2bufc(DEX_CMD_STATUS);
			break;
		default:
			dex->request = DEX_REQ_NONE;
	}

	dex->ptr_out = dex->buf_out;
	dex_tty_write(dex);

	PDEBUG("< dex_write_cmd");
}

#define mkpair(req, reply) (((req) << 8) | (reply))
static int dex_read_cmd (struct dex_device *dex)
{
	int reply = dex->buf_in[3];
	int n_args = dex->count_in - 4;

	PDEBUG("> dex_read_cmd(%p) [ reply:%i n_args:%i ]", dex, reply, n_args);

	if (dex->count_in < 4)
		return(0);

	/* There should be a better way to do this... */
	if ((dex->request == DEX_REQ_ON) || (dex->request == DEX_REQ_OFF)) {
		PDEBUG("faking CMD_OK for CMD_LIGHT");
		reply = DEX_CMD_OK;
	}

	if (dex->request == DEX_REQ_MAGIC) {
		PDEBUG("faking CMD_OK for CMD_MAGIC");
		reply = DEX_CMD_OK;
	}

	if (reply == DEX_CMD_ERROR) {
		PDEBUG("got CMD_ERROR");
		return -EIO;
	}

	if (reply == DEX_CMD_POUT) {
		PDEBUG("got CMD_POUT");
		return -EIO;
	}

	switch (mkpair(dex->request, reply)) {
		case mkpair(DEX_REQ_READ, DEX_CMD_DATA):
			if (n_args < 129) return 0;
			if ((dex_checksum((dex->buf_in + 4), 129) ^
				lsb(dex->request_n) ^ msb(dex->request_n)) != 0) {
				return -EIO;
			}
			memcpy(dex->request_ptr, (dex->buf_in + 4), 128);
			return 1;
		case mkpair(DEX_REQ_WRITE, DEX_CMD_WOK):
		case mkpair(DEX_REQ_WRITE, DEX_CMD_WSAME):
			return 1;
		case mkpair(DEX_REQ_READ, DEX_CMD_OK):
		case mkpair(DEX_REQ_WRITE, DEX_CMD_OK):
			return -EIO;
		case mkpair(DEX_REQ_INIT, DEX_CMD_ID):
			if (n_args < 5) return 0;
			return 1;
		case mkpair(DEX_REQ_MAGIC, DEX_CMD_OK):
		case mkpair(DEX_REQ_ON, DEX_CMD_OK):
		case mkpair(DEX_REQ_OFF, DEX_CMD_OK):
			return 1;
		case mkpair(DEX_REQ_STATUS, DEX_CMD_OK):
			dex->media_change = 1;
			dex->media_present = 0;
			return 1;
		case mkpair(DEX_REQ_STATUS, DEX_CMD_OKCARD):
			if (n_args < 1) return 0;
			dex->media_present = 1;
			// Should autodetect or something
			//blk_size[major][dex->minor] = 128 * 1024;
			return 1;
		default:
			PDEBUG("got unknown reply %i from device", reply);
			return -EIO;
	}

	PDEBUG("< dex_read_cmd");
}
#undef mkpair

static void dex_check_reply (struct dex_device *dex)
{
	int ret;

	PDEBUG("> dex_check_reply(%p)", dex);

	ret = dex_read_cmd(dex);
	PDEBUG(" got %i", ret);
	if (ret != 0) {
		dex->request = DEX_REQ_NONE;
		dex->request_return = ret < 0 ? ret : 0;
		wake_up_interruptible(&dex->request_wait);
	}

	PDEBUG("< dex_check_reply");
}

static int dex_do_cmd (struct dex_device *dex, int cmd)
{
	PDEBUG("> dex_do_cmd(%p, %d", dex, cmd);

	dex->request = cmd;
	dex->request_return = -EIO;

	dex_write_cmd(dex);
	// Race condition here :(
	interruptible_sleep_on_timeout(&dex->request_wait, DEX_TIMEOUTJ);

	PDEBUG("< dex_do_cmd");

	return dex->request_return;
}


static int dex_transfer(struct dex_device *dex,
			unsigned int sector, unsigned int len,
			char *buffer, int write)
{
	int error = 0;

	PDEBUG("> dex_transfer(%p, %u, %u, %p, %i", dex, sector, len,
					buffer, write);

	for (; len > 0; sector++, len--) {
		dex->request_n = sector;
		dex->request_ptr = buffer;

		dex_do_cmd(dex, DEX_REQ_INIT);
		dex_do_cmd(dex, DEX_REQ_MAGIC);

		error = dex_do_cmd(dex, write ? DEX_REQ_WRITE : DEX_REQ_READ);

		if (error < 0)
			break;

		buffer += 128;
	}

	PDEBUG("< dex_transfer := %i", error);

	return error;
}


/* tty functions */

static void dex_tty_write (struct dex_device *dex)
{
	int i;

	if (dex->count_out > 0) {
		PDEBUG("writing %d bytes to device", dex->count_out);

		i = dex->tty->ops->write(dex->tty, dex->ptr_out, dex->count_out);
		dex->ptr_out += i;
		dex->count_out -= i;

		PDEBUG("(%d bytes were written)", i);

		if (dex->count_out > 0)
			set_bit(TTY_DO_WRITE_WAKEUP, &dex->tty->flags);
		else
			clear_bit(TTY_DO_WRITE_WAKEUP, &dex->tty->flags);
	}
}

static void dex_receive_buf (struct tty_struct *tty, const unsigned char *buf,
				char *fp, int count)
{
	struct dex_device *dex = tty->disc_data;
	unsigned long flags;

	PDEBUG("> dex_receive_buf(%p, %p, %p, %u)", tty, buf, fp, count);

	spin_lock_irqsave(&dex->lock, flags);
	if(dex->request) {
		if (count > DEX_BUFSIZE_IN - dex->count_in) {
			warn("Input buffer overflowing");
			count = DEX_BUFSIZE_IN - dex->count_in;
		}
		memcpy(dex->buf_in + dex->count_in, buf, count);
		dex->count_in += count;
		dex_check_reply(dex);
	}
	spin_unlock_irqrestore(&dex->lock, flags);

	PDEBUG("< dex_receive_buf");
}

static void dex_write_wakeup (struct tty_struct *tty)
{
	struct dex_device *dex = tty->disc_data;
	unsigned long flags;

	PDEBUG("> dex_write_wakeup(%p)", tty);

	spin_lock_irqsave(&dex->lock, flags);
	dex_tty_write(dex);
	spin_unlock_irqrestore(&dex->lock, flags);

	PDEBUG("< dex_write_wakeup");
}

/*
int dex_tty_ioctl (struct tty_struct *tty, struct file *filp,
		unsigned int cmd, unsigned long arg) {
	struct dex_device *dex = tty->disc_data;
	unsigned long flags;
	int ret, minor=0;

	PDEBUG("> dex_tty_ioctl(%p, %p, %u, %lu)", tty, filp, cmd, arg);

	if (_IOC_TYPE(cmd) != DEX_IOC_MAGIC) return -ENOTTY;

	if ((_IOC_DIR(cmd) & _IOC_READ) &&
		!access_ok(VERIFY_WRITE, arg, _IOC_SIZE(cmd)))
		return -EFAULT;
	if ((_IOC_DIR(cmd) & _IOC_WRITE) &&
		!access_ok(VERIFY_READ, arg, _IOC_SIZE(cmd)))
		return -EFAULT;

	spin_lock_irqsave(&dex->lock, flags);

	switch (cmd) {
		case DEX_IOCGMAJOR:
			ret = __put_user(major, (int *)arg);
			break;
		case DEX_IOCGMINOR:
			ret = dex->minor >= 0 ?
				__put_user(dex->minor, (int *)arg) :
				-EIO;
			break;
		case DEX_IOCSMINOR:
			ret = dex->minor < 0 ?
				__get_user(minor, (int *)arg) :
				-EIO;
			if (ret == 0) {
				if (dex_devices[minor] == NULL) {
					dex->minor = minor;
					dex_devices[minor] = dex;
				} else {
					ret = -EBUSY;
				}
			}
			break;
		default:
			ret = -ENOTTY;
	}

	spin_unlock_irqrestore(&dex->lock, flags);

	PDEBUG("< dex_tty_ioctl := %d", ret);
	return ret;
}
*/

static int dex_make_request (struct request_queue *, struct bio *);
extern struct block_device_operations dex_bdops;
static int dex_thread (void *);
static int dex_tty_open (struct tty_struct *tty)
{
	struct dex_device *tmp;

	PDEBUG("> dex_tty_open(%p)", tty);

	if((tmp = kmalloc(sizeof(struct dex_device), GFP_KERNEL)) == NULL) {
		warn("cannot allocate device struct");
		return -ENOMEM;
	}

	spin_lock_init(&tmp->lock);
	init_waitqueue_head(&tmp->request_wait);

	tmp->tty = tty;
	tmp->open_count = 0;
	tmp->request = DEX_REQ_NONE;
	tmp->media_change = 0;
	tmp->minor = -1;

	tty->disc_data = tmp;
	tty->receive_room = DEX_BUFSIZE_IN;

	tmp->request_queue = blk_alloc_queue(GFP_KERNEL);
	tmp->request_queue->queuedata = tmp;
	blk_queue_make_request(tmp->request_queue, dex_make_request);

	tmp->bio_head = tmp->bio_tail = NULL;

	init_waitqueue_head(&tmp->thread_wait);
	tmp->thread = kthread_run(dex_thread, tmp, "dexdrive%d", 0);

	if (IS_ERR(tmp->thread)) {
		warn("cannot create thread");
		/* FIXME: We need to clean up here */
	}

	tmp->gd = alloc_disk(1);
	if (! tmp->gd) {
		warn("cannot allocate gendisk struct");
		// We need to clean up our mess
		return -1;
	}
	tmp->gd->major = major;
	tmp->gd->first_minor = 0;
	tmp->gd->fops = &dex_bdops;
	tmp->gd->queue = tmp->request_queue;
	tmp->gd->private_data = tmp;
	snprintf(tmp->gd->disk_name, 32, "dexdrive%u", 0);
	set_capacity(tmp->gd, 128 * 2);
	add_disk(tmp->gd);

	PDEBUG("< dex_tty_open := %d", 0);
	return 0;
}

static void dex_tty_close (struct tty_struct *tty)
{
	struct dex_device *dex = tty->disc_data;

	PDEBUG("> dex_tty_close(%p)", tty);

	// check for dex->open_count == 0

	tty->disc_data = NULL;

	del_gendisk(dex->gd);
	put_disk(dex->gd);

	if (dex->request_queue)
		blk_cleanup_queue(dex->request_queue);

	kthread_stop(dex->thread);

	/* FIXME: The thread could still be running here */
	kfree(dex);

	PDEBUG("< dex_tty_close");
}

static struct tty_ldisc dex_ldisc = {
	.magic		= TTY_LDISC_MAGIC,
	.owner		= THIS_MODULE,
	.name		= DEX_NAME,
	.open		= dex_tty_open,
	.close		= dex_tty_close,
	/* .ioctl	= dex_tty_ioctl, */
	.receive_buf	= dex_receive_buf,
	.write_wakeup	= dex_write_wakeup,
};


/* Block device functions */

static inline void dex_handle_bio(struct dex_device *dex, struct bio *bio)
{
	sector_t sector;
	struct bio_vec *bvec;
	int i;
	int error = 0;
	
	PDEBUG(">> dex_handle_bio(%p, %p)", dex, bio);

	sector = bio->bi_sector << 2;

	bio_for_each_segment(bvec, bio, i) {
		sector_t len = (bvec->bv_len >> 7);

		if ((bvec->bv_len & 0x7f) != 0) {
			warn (KERN_NOTICE "Partial read/write\n");
			error = -EIO;
			break;
		}

		error = dex_transfer(dex, sector, len,
					kmap(bvec->bv_page) + bvec->bv_offset,
					bio_data_dir(bio) == WRITE);

		if (error < 0)
			break;

		sector += len;
	}

	bio_endio(bio, error);

	PDEBUG("<< dex_handle_bio");
}

static void dex_add_bio(struct dex_device *dex, struct bio *bio)
{
	if (dex->bio_tail) {
		dex->bio_tail->bi_next = bio;
        } else {
		dex->bio_head = bio;
	}

	dex->bio_tail = bio;
}

static struct bio *dex_get_bio(struct dex_device *dex)
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


static int dex_make_request (struct request_queue *queue, struct bio *bio)
{
	struct dex_device *dex = queue->queuedata;

	PDEBUG("> dex_make_request(%p, %p)", queue, bio);

	spin_lock_irq(&dex->lock);
	dex_add_bio(dex, bio);
	wake_up(&dex->thread_wait);
	spin_unlock_irq(&dex->lock);

	PDEBUG("< dex_make_request");

	return 0;
}

static int dex_thread (void *data)
{
	struct dex_device *dex = data;
	struct bio *bio;

	PDEBUG(">> dex_thread starting");

	// set_user_nice(current, -20);

	while (!kthread_should_stop() || dex->bio_head) {
		/* TODO: ping the device regularly */
		wait_event_interruptible(dex->thread_wait,
				dex->bio_head || kthread_should_stop());

		if (! dex->bio_head)
			continue;

		spin_lock_irq(&dex->lock);
		bio = dex_get_bio(dex);
		spin_unlock_irq(&dex->lock);

		dex_handle_bio(dex, bio);
	}

	PDEBUG("<< dex_thread exiting");

	return 0;
}

static int dex_open (struct inode *inode, struct file *filp)
{
	struct dex_device *dex;
	unsigned long flags;

	PDEBUG("> dex_open(%p, %p)", inode, filp);

	dex = inode->i_bdev->bd_disk->private_data;

	spin_lock_irqsave(&dex->lock, flags);
	dex->open_count++;
	spin_unlock_irqrestore(&dex->lock, flags);

	PDEBUG("< dex_open := %d", 0);
	return 0;
}

static int dex_release (struct inode *inode, struct file *filp)
{
	struct dex_device *dex;
	unsigned long flags;

	PDEBUG("> dex_release(%p, %p)", inode, filp);

	dex = inode->i_bdev->bd_disk->private_data;
	spin_lock_irqsave(&dex->lock, flags);
	dex->open_count--;
	spin_unlock_irqrestore(&dex->lock, flags);

	PDEBUG("< dex_release := %d", 0);
	return 0;
}

struct block_device_operations dex_bdops = {
	.owner			= THIS_MODULE,
	.open			= dex_open,
	.release		= dex_release,
};


/* Module functions */

static void dex_cleanup (void)
{
	PDEBUG("> dex_cleanup()");
	if (tty_register_ldisc(DEX_LDISC, NULL) != 0) {
		warn("can't unregister ldisc");
	}
	unregister_blkdev(major, DEX_NAME);
	PDEBUG("< dex_cleanup");
}

static int __init dex_init (void)
{
	int tmp;

	PDEBUG("> dex_init()");
	if ((tmp = register_blkdev(major, DEX_NAME)) < 0) {
		warn("can't get major %d", major);
		return tmp;
	}
	if (major == 0) major = tmp;
	PDEBUG("setting major to %d", major);

	if (tty_register_ldisc(DEX_LDISC, &dex_ldisc) != 0) {
		warn("can't set ldisc");
		dex_cleanup();
		return -1;
	}

	PDEBUG("< dex_init := %d", 0);
	return 0;
}



module_init(dex_init);
module_exit(dex_cleanup);


MODULE_AUTHOR("fbriere");
MODULE_DESCRIPTION("blabla");
MODULE_LICENSE("GPL");

