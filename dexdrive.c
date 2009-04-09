/* Missing stuff...
 *
 * - command retries
 */

#define DEX_NAME  "dexdrive"
#define DEX_MAJOR 251
#define DEX_LDISC N_X25  // Find one in include/asm/termios.h
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

#include <linux/module.h>

unsigned int major = DEX_MAJOR;
#include <linux/blkdev.h>

#include <linux/tty.h>
#include <linux/tty_ldisc.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <asm/uaccess.h>

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
	/* temp variable for requests */
	int request_tmp;
	/* wait queue to wake up when request is completed */
	wait_queue_head_t request_wait;
	/* where to store return value of request */
	int *request_return;
	/* we are in the process of talking with the device */
	int active;
	/* input and output buffers */
	char buf_in[DEX_BUFSIZE_IN], buf_out[DEX_BUFSIZE_OUT];
	/* number of bytes read / to write / written */
	int count_in, count_out, count_out_real;
	int media_present;
	int media_change;
	int minor;
	struct gendisk *gd;
	struct request_queue *request_queue;
	int io_request;
};

struct dex_device * dex_devices[1];


/* Helper functions */

inline int reverse_int (int x) {
	int i, res = 0;
	for (i = 0; i < 4; i++) {
		res |= ((x & (1 << i)) << (7 - (2 * i)));
		res |= ((x & (1 << (7 - i))) >> (7 - (2 * i)));
	}
	return res;
}

inline char dex_checksum (char *ptr, int len) {
	char res = 0;
	int i;

	for (i = 0; i < len; i++)
		res ^= ptr[i];

	return res;
}


/* Data transfer */

void dex_end_request (struct dex_device *dex, int x) {
	struct request *req;
	unsigned long flags;

	PDEBUG("> dex_end_request(%p, %d)", dex, x);

	dex->active = 0;

	if (dex->io_request) {
		spin_lock_irqsave(&dex->request_queue->queue_lock, flags);
		req = elv_next_request(dex->request_queue);
		end_request(req, 1);
		spin_unlock_irqrestore(&dex->request_queue->queue_lock, flags);
	} else {
		if (dex->request_return != NULL) {
			*dex->request_return = x ? 0 : EIO;
			dex->request_return = NULL;
		}
		wake_up_interruptible(&dex->request_wait);
	}

	dex->request = DEX_REQ_NONE;

	PDEBUG("< dex_end_request");
}


void dex_write_cmd (struct dex_device *dex) {
	int block;

	PDEBUG("> dex_write_cmd(%p)", dex);

	dex->count_out = dex->count_in = 0;
	add2bufs(DEX_CMD_PREFIX, sizeof(DEX_CMD_PREFIX)-1);
	switch (dex->request) {
		case DEX_REQ_READ:
			add2bufc(DEX_CMD_READ);
			block = (dex->request_n * 4) + dex->request_tmp;
			add2bufc(lsb(block));
			add2bufc(msb(block));
			break;
		case DEX_REQ_WRITE:
			add2bufc(DEX_CMD_WRITE);
			block = (dex->request_n * 4) + dex->request_tmp;
			add2bufc(msb(block));
			add2bufc(lsb(block));
			add2bufc(reverse_int(msb(block)));
			add2bufc(reverse_int(lsb(block)));
			add2bufs((dex->request_ptr + (dex->request_tmp * 128)),
					128);
			add2bufc(dex_checksum((dex->buf_out + 4), 132));
			break;
		case DEX_REQ_INIT:
			if(dex->request_tmp == 0) {
				add2bufc(DEX_CMD_INIT);
				add2bufs(DEX_INIT_STR, sizeof(DEX_INIT_STR)-1);
			} else {
				add2bufc(DEX_CMD_MAGIC);
			}
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

	dex->active = 1;
	dex->tty->flags |= (1 << TTY_DO_WRITE_WAKEUP);
	PDEBUG("writing %d bytes to device", dex->count_out);
	dex->count_out_real = dex->tty->ops->write(dex->tty,
			dex->buf_out, dex->count_out);

	PDEBUG("< dex_write_cmd");
}

#define mkpair(req, reply) (((req) << 8) | (reply))
void dex_read_cmd (struct dex_device *dex) {
	int reply = dex->buf_in[3];

	PDEBUG("> dex_read_cmd(%p)", dex);

	/* There should be a better way to do this... */
	if ((dex->request == DEX_REQ_ON) || (dex->request == DEX_REQ_OFF)) {
		PDEBUG("faking CMD_OK for CMD_LIGHT");
		reply = DEX_CMD_OK;
	}

	if ((dex->request == DEX_REQ_INIT) && (dex->request_tmp == 1)) {
		PDEBUG("faking CMD_OK for CMD_MAGIC");
		reply = DEX_CMD_OK;
	}

	if (reply == DEX_CMD_ERROR) {
		PDEBUG("got CMD_ERROR");
		dex_end_request(dex, 0);
		return;
	}

	switch (mkpair(dex->request, reply)) {
		case mkpair(DEX_REQ_READ, DEX_CMD_DATA):
			if ((dex_checksum((dex->buf_in + 4), 129) ^
				lsb(dex->request_n) ^ msb(dex->request_n)) != 0) {
				dex_end_request(dex, 0);
				break;
			}
			memcpy((dex->request_ptr + (dex->request_tmp * 128)),
					(dex->buf_in + 4), 128);
			if (++dex->request_tmp == 4) {
				dex_end_request(dex, 1);
			} else {
				dex_write_cmd(dex);
			}
			break;
		case mkpair(DEX_REQ_WRITE, DEX_CMD_WOK):
		case mkpair(DEX_REQ_WRITE, DEX_CMD_WSAME):
			dex_end_request(dex, 1);
			break;
		case mkpair(DEX_REQ_READ, DEX_CMD_OK):
		case mkpair(DEX_REQ_WRITE, DEX_CMD_OK):
			dex_end_request(dex, 0);
			break;
		case mkpair(DEX_REQ_INIT, DEX_CMD_ID):
			dex->request_tmp++;
			dex_write_cmd(dex);
			break;
		case mkpair(DEX_REQ_INIT, DEX_CMD_OK):
		case mkpair(DEX_REQ_ON, DEX_CMD_OK):
		case mkpair(DEX_REQ_OFF, DEX_CMD_OK):
			dex_end_request(dex, 1);
			break;
		case mkpair(DEX_REQ_STATUS, DEX_CMD_OK):
			dex->media_change = 1;
			dex->media_present = 0;
			dex_end_request(dex, 1);
			break;
		case mkpair(DEX_REQ_STATUS, DEX_CMD_OKCARD):
			dex->media_present = 1;
			// Should autodetect or something
			//blk_size[major][dex->minor] = 128 * 1024;
			dex_end_request(dex, 1);
			break;
		default:
			PDEBUG("got unknown reply from device");
			dex_end_request(dex, 0);
	}

	PDEBUG("< dex_read_cmd");
}
#undef mkpair

int dex_check_reply (struct dex_device *dex) {
	int i = -1;

	PDEBUG("> dex_check_reply(%p)", dex);

	if (dex->count_in < 4)
		return(0);

	switch (dex->buf_in[3]) {
		case DEX_CMD_POUT:
		case DEX_CMD_ERROR:
		case DEX_CMD_OK:
		case DEX_CMD_WOK:
		case DEX_CMD_WSAME:
			i = 0;
			break;
		case DEX_CMD_ID:
			i = 5;
			break;
		case DEX_CMD_DATA:
			i = 129;
			break;
		case DEX_CMD_OKCARD:
			switch (dex->request) {
				case DEX_REQ_PAGE:
					i = 0;
					break;
				case DEX_REQ_STATUS:
					i = 1;
					break;
			}
			break;
		case DEX_CMD_WAIT:
			if ( (dex->count_in > 0) &&
					((dex->count_in % 4) == 0) &&
					(dex->buf_in[ dex->count_in - 1 ] !=
					 DEX_CMD_WAIT)) {
				i = dex->count_in - 4;
			}
			break;
		default:
			PDEBUG("check_reply: what command did I send?");
	}

	i += 4;

	PDEBUG("< dex_check_reply := %d", (dex->count_in >= i));
	return (dex->count_in >= i);
}


void dex_do_cmd (struct dex_device *dex, int cmd, int io_request) {
	PDEBUG("> dex_do_cmd(%p, %d, %d", dex, cmd, io_request);
	dex->request = cmd;
	dex->request_tmp = 0;
	dex->io_request = io_request;
	dex_write_cmd(dex);
	PDEBUG("< dex_do_cmd");
}


/* tty functions */

void dex_receive_buf (struct tty_struct *tty, const unsigned char *buf,
			char *fp, int count) {
	struct dex_device *dex = tty->disc_data;
	unsigned long flags;

	PDEBUG("> dex_receive_buf(%p, %p, %p, %u)", tty, buf, fp, count);

	spin_lock_irqsave(&dex->lock, flags);
	if(dex->active) {
		if (count > DEX_BUFSIZE_IN - dex->count_in) {
			warn("Input buffer overflowing");
			count = DEX_BUFSIZE_IN - dex->count_in;
		}
		memcpy(dex->buf_in + dex->count_in, buf, count);
		dex->count_in += count;
		if (dex_check_reply(dex)) {
			dex_read_cmd(dex);
		}
	}
	spin_unlock_irqrestore(&dex->lock, flags);

	PDEBUG("< dex_receive_buf");
}

void dex_write_wakeup (struct tty_struct *tty) {
	struct dex_device *dex = tty->disc_data;
	unsigned long flags;
	int i;

	PDEBUG("> dex_write_wakeup(%p)", tty);

	spin_lock_irqsave(&dex->lock, flags);
	if (dex->active && dex->count_out_real < dex->count_out) {
		i = tty->ops->write(tty,
				(dex->buf_out + dex->count_out_real),
				(dex->count_out - dex->count_out_real));
		dex->count_out_real += i;
	}
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

void dex_request (struct request_queue *queue);
extern struct block_device_operations dex_bdops;
int dex_tty_open (struct tty_struct *tty) {
	struct dex_device *tmp;
	unsigned long flags;
	int ret = -1;

	PDEBUG("> dex_tty_open(%p)", tty);

	if((tmp = kmalloc(sizeof(struct dex_device), GFP_ATOMIC)) == NULL) {
		warn("cannot allocate device struct");
		return -ENOMEM;
	}

	spin_lock_init(&tmp->lock);
	tmp->request_queue = blk_init_queue(dex_request, &tmp->lock);
	init_waitqueue_head(&tmp->request_wait);

	tmp->tty = tty;
	tmp->open_count = 0;
	tmp->request = DEX_REQ_NONE;
	tmp->active = 0;
	tmp->media_change = 0;
	tmp->minor = -1;

	tty->disc_data = tmp;
	tty->receive_room = DEX_BUFSIZE_IN;

	tmp->request_return = &ret;
	spin_lock_irqsave(&tmp->lock, flags);
	dex_do_cmd(tmp, DEX_REQ_INIT, 0);
	spin_unlock_irqrestore(&tmp->lock, flags);
	// Race condition here :(
	interruptible_sleep_on_timeout(&tmp->request_wait, DEX_TIMEOUTJ);

	if(ret != 0) {
		kfree(tmp);
		return -EIO;
	}

	MOD_INC_USE_COUNT;

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

void dex_tty_close (struct tty_struct *tty) {
	struct dex_device *dex = tty->disc_data;

	PDEBUG("> dex_tty_close(%p)", tty);

	// check for dex->open_count == 0

	dex_devices[0] = NULL;

	del_gendisk(dex->gd);
	put_disk(dex->gd);

	if (dex->request_queue)
		blk_cleanup_queue(dex->request_queue);

	kfree(dex);

	MOD_DEC_USE_COUNT;

	PDEBUG("< dex_tty_close");
}

struct tty_ldisc dex_ldisc = {
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

void dex_request (struct request_queue *queue) {
	struct dex_device *dex;
	struct request *req;

	PDEBUG("> dex_request(%p)", queue);

	while ((req = elv_next_request(queue)) != NULL) {
		PDEBUG("checking request head");

		dex = dex_devices[0];
		if (dex == NULL)
			PDEBUG("request called with dex null -- dammit!");

		if (dex->request != DEX_REQ_NONE) {
			PDEBUG("device is busy");
			return;
		}

		if (rq_data_dir(req) == 0) {
				dex->request_n = req->sector;
				dex->request_ptr = req->buffer;
				dex_do_cmd(dex, DEX_REQ_READ, 1);
		} else {
				dex->request_n = req->sector;
				dex->request_ptr = req->buffer;
				dex_do_cmd(dex, DEX_REQ_WRITE, 1);
		}
	}

	PDEBUG("< dex_request");
}

int dex_open (struct inode *inode, struct file *filp) {
	struct dex_device *dex;
	unsigned long flags;

	PDEBUG("> dex_open(%p, %p)", inode, filp);

	dex = dex_devices[0];
	if (dex == NULL) {
		PDEBUG("you cannot open device w/o ldisc");
		return -ENXIO;
	}

	spin_lock_irqsave(&dex->lock, flags);
	dex->open_count++;
	spin_unlock_irqrestore(&dex->lock, flags);

	PDEBUG("< dex_open := %d", 0);
	return 0;
}

int dex_release (struct inode *inode, struct file *filp) {
	struct dex_device *dex;
	unsigned long flags;

	PDEBUG("> dex_release(%p, %p)", inode, filp);

	dex = dex_devices[0];
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

void dex_cleanup (void) {
	PDEBUG("> dex_cleanup()");
	if (tty_register_ldisc(DEX_LDISC, NULL) != 0) {
		warn("can't unregister ldisc");
	}
	unregister_blkdev(major, DEX_NAME);
	PDEBUG("< dex_cleanup");
}

int dex_init (void) {
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

EXPORT_NO_SYMBOLS;

