/*
 * Declarations to provide compatibility with all kernel versions from
 * 2.6.25 up, without littering the code with #ifdefs all over.
 */

#include <linux/version.h>


/*
 * The prototypes for open() and release() in struct block_device_operations
 * changed considerably in 2.6.28.
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)

#define COMPAT_OPEN_PARAMS		struct inode *inode, struct file *filp
#define COMPAT_RELEASE_PARAMS		struct inode *inode, struct file *filp
#define compat_open_get_disk()		(inode->i_bdev->bd_disk)
#define compat_release_get_disk()	(inode->i_bdev->bd_disk)
#define compat_open_get_bdev()		(inode->i_bdev)

#else

#define COMPAT_OPEN_PARAMS		struct block_device *bdev, fmode_t mode
#define COMPAT_RELEASE_PARAMS		struct gendisk *disk, fmode_t mode
#define compat_open_get_disk()		(bdev->bd_disk)
#define compat_release_get_disk()	disk
#define compat_open_get_bdev()		bdev

#endif


/* hardsect_size was renamed to logical_block_size in 2.6.31 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
# define blk_queue_logical_block_size blk_queue_hardsect_size
#endif

/* This was defined in 2.6.28 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
# define disk_to_dev(disk)	(&(disk)->dev)
#endif

/* struct tty_ldisc was renamed to tty_ldisc_ops in 2.6.27 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
# define tty_ldisc_ops tty_ldisc
#endif

/* tty_operations were moved to tty->ops in 2.6.26 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
# define compat_tty_write(tty)		tty->driver->write
#else
# define compat_tty_write(tty)		tty->ops->write
#endif

