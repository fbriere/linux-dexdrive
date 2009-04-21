/*
 * Declarations to provide compatibility with all kernel versions from
 * 2.6.26 up, without littering the code with #ifdefs all over.
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


/* struct tty_ldisc was renamed to tty_ldisc_ops in 2.6.27 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
# define tty_ldisc_ops tty_ldisc
#endif

