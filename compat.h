/*
 * Declarations to provide compatibility with all kernel versions from
 * 3.0 up, without littering the code with #ifdefs all over.
 */

#include <linux/version.h>


/* (*make_request_fn)() return type was changed in 3.2, 4.4 and 5.16 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
# define COMPAT_REQUEST_RETTYPE		int
# define COMPAT_REQUEST_RETURN()	return(0)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
# define COMPAT_REQUEST_RETTYPE		void
# define COMPAT_REQUEST_RETURN()	return
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5,16,0)
# define COMPAT_REQUEST_RETTYPE		blk_qc_t
# define COMPAT_REQUEST_RETURN()	return(BLK_QC_T_NONE)
#else
# define COMPAT_REQUEST_RETTYPE		void
# define COMPAT_REQUEST_RETURN()	return
#endif

/* block_device_operations->release() returns void since 3.10 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
# define COMPAT_RELEASE_RETTYPE         int
# define COMPAT_RELEASE_RETURN(ret)     return(ret)
#else
# define COMPAT_RELEASE_RETTYPE         void
# define COMPAT_RELEASE_RETURN(ret)     return
#endif

/* bio->bi_sector moved to bio->bi_iter.bi_sector in 3.14 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
# define compat_bio_bi_sector(bio)        bio->bi_sector
#else
# define compat_bio_bi_sector(bio)        bio->bi_iter.bi_sector
#endif

/* bio_for_each_segment() argument types changed in 3.14 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
# define COMPAT_BIO_VEC_TYPE            struct bio_vec *
# define COMPAT_BVEC_ITER_TYPE          int
# define compat_bvec(bvec)              (*bvec)
#else
# define COMPAT_BIO_VEC_TYPE            struct bio_vec
# define COMPAT_BVEC_ITER_TYPE          struct bvec_iter
# define compat_bvec(bvec)              bvec
#endif

/* bio errors are signaled via bio->bi_error since 4.3 */
/* (now bi_status since 4.13) */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0)
# define compat_bio_endio(bio, error)   bio_endio(bio, error)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
# define compat_bio_endio(bio, error)   bio->bi_error = error; bio_endio(bio)
#else
# define compat_bio_endio(bio, error)   bio->bi_status = error; bio_endio(bio)
#endif

/* request_queue->backing_dev_info is now a pointer since 4.11 */
/* request_queue->backing_dev_info moved to disk->bdi in 5.15 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)
# define compat_backing_dev_info_ptr(request_queue, disk)  (&(request_queue->backing_dev_info))
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5,15,0)
# define compat_backing_dev_info_ptr(request_queue, disk)  request_queue->backing_dev_info
#else
# include <linux/backing-dev-defs.h>
# define compat_backing_dev_info_ptr(request_queue, disk)  disk->bdi
#endif

/* blk_alloc_queue() and blk_queue_make_request() were merged in 5.7 */
/* blk_alloc_queue() no longer takes a function pointer since 5.9 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0)
# define compat_blk_alloc_queue(fn)                blk_alloc_queue(GFP_KERNEL)
# define compat_blk_queue_make_request(queue, fn)  blk_queue_make_request(queue, fn)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5,9,0)
# define compat_blk_alloc_queue(fn)                blk_alloc_queue(fn, NUMA_NO_NODE)
# define compat_blk_queue_make_request(queue, fn)
#else
# define compat_blk_alloc_queue(fn)                blk_alloc_queue(NUMA_NO_NODE)
# define compat_blk_queue_make_request(queue, fn)
#endif


/* Since 5.9, the make_request() function no longer receives the queue as
 * argument, and is now set via a block_device_operations.submit_bio field. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,9,0)

#define COMPAT_REQUEST_PARAMS		struct request_queue *queue, struct bio *bio
#define compat_request_get_queue()	queue
#define COMPAT_SET_SUBMIT_BIO(fn)

#else

#define COMPAT_REQUEST_PARAMS		struct bio *bio
/* Since 5.12, this pointer needs an extra indirection. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,12,0)
# define compat_request_get_queue()	(bio->bi_disk->queue)
#else
# define compat_request_get_queue()	(bio->bi_bdev->bd_disk->queue)
#endif
/* (Notice the trailing comma) */
#define COMPAT_SET_SUBMIT_BIO(fn)	.submit_bio = (fn),

#endif

/* check_disk_change() was removed in 5.10 */
/* Its argument type was further changed in 6.5; see the definition of
 * compat_block_open_checkchg_arg() below. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0)
# define compat_check_disk_change(bdev)  check_disk_change(bdev)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(6,5,0)
# define compat_check_disk_change(bdev)  bdev_check_media_change(bdev)
#else
# define compat_check_disk_change(disk)  disk_check_media_change(disk)
#endif

/* ldisc_ops.magic was removed in 5.13 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,13,0)
/* (Notice the trailing comma) */
# define COMPAT_SET_MAGIC	.magic = TTY_LDISC_MAGIC,
#else
# define COMPAT_SET_MAGIC
#endif

/* tty_ldisc has seen many changes in 5.14:
 *  - The fp argument to tty_ldisc_ops.receive_buf() is now marked as const.
 *  - The disc argument to tty_register_ldisc() has been removed; the caller
 *    now sets tty_ldisc_ops.num themselves beforehand.
 *  - Similarly, the disc argument to tty_unregister_ldisc() has been
 *    replaced with a tty_ldisc_ops, with .num acting in its stead.
 *  - tty_unregister_ldisc() no longer returns anything.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,14,0)
# define COMPAT_TTY_RECEIVE_BUF_CONST
# define compat_tty_register_ldisc(disc, new_ldisc) \
	tty_register_ldisc(disc, new_ldisc)
# define compat_tty_unregister_ldisc(ldisc) \
	tty_unregister_ldisc((ldisc)->num)
#else
# define COMPAT_TTY_RECEIVE_BUF_CONST	const
/* (Statement expressions are supported both by GCC and Clang) */
# define compat_tty_register_ldisc(disc, new_ldisc) \
	({ (new_ldisc)->num = disc; tty_register_ldisc(new_ldisc); })
# define compat_tty_unregister_ldisc(ldisc) \
	({ tty_unregister_ldisc(ldisc); 0; })
#endif
/* Since 6.6, the fp argument is also marked as unsigned, and `count` is
 * now of type size_t. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,6,0)
# define COMPAT_TTY_RECEIVE_BUF_UNSIGNED
# define COMPAT_TTY_RECEIVE_BUF_COUNT_TYPE	int
#else
# define COMPAT_TTY_RECEIVE_BUF_UNSIGNED	unsigned
# define COMPAT_TTY_RECEIVE_BUF_COUNT_TYPE	size_t
#endif

/* 5.14 introduces blk_alloc_disk(), which automatically allocates a
 * request_queue along with the gendisk.  Among other things, this requires
 * us to change the order in which we initialize both structures. */
/* Since 6.9, blk_alloc_disk() also requires a queue_limits pointer as first
 * argument. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,14,0)
# undef COMPAT_USES_BLK_ALLOC_DISK
# undef COMPAT_USES_BLK_ALLOC_DISK_WITH_LIMITS
# define compat_blk_alloc_disk(lim)	alloc_disk(1)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(6,9,0)
# define COMPAT_USES_BLK_ALLOC_DISK
# undef COMPAT_USES_BLK_ALLOC_DISK_WITH_LIMITS
# define compat_blk_alloc_disk(lim)	blk_alloc_disk(NUMA_NO_NODE)
#else
# define COMPAT_USES_BLK_ALLOC_DISK
# define COMPAT_USES_BLK_ALLOC_DISK_WITH_LIMITS
# define compat_blk_alloc_disk(lim)	blk_alloc_disk(&lim, NUMA_NO_NODE)
#endif
/* blk_cleanup_disk() was further removed in 6.0 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,14,0)
# define compat_blk_cleanup(dex) \
	do { \
		if (dex->gd) \
			put_disk(dex->gd); \
		if (dex->request_queue) \
			blk_cleanup_queue(dex->request_queue); \
	} while (0)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0)
# define compat_blk_cleanup(dex) \
	if (dex->gd) \
		blk_cleanup_disk(dex->gd)
#else
# define compat_blk_cleanup(dex)	put_disk(dex->gd)
#endif

/* add_disk() now returns a value in 5.15, marked __must_check in 5.16 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,15,0)
# define compat_add_disk(disk)		(add_disk(disk), 0)
# else
# define compat_add_disk(disk)		add_disk(disk)
#endif

/* Since 5.17, ioctl() no longer takes a `file` argument. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,17,0)
#define COMPAT_IOCTL_PARAMS		struct tty_struct *tty, \
					struct file *file, \
					unsigned int cmd, \
					unsigned long arg
#else
#define COMPAT_IOCTL_PARAMS		struct tty_struct *tty, \
					unsigned int cmd, \
					unsigned long arg
#endif

/* The signatures of .open and .release were changed in 6.5
 *
 * Within .open, compat_block_open_disk_ref returns a reference to the
 * gendisk, while compat_block_open_checkchg_arg is the single argument
 * that should be passed to compat_check_disk_change(). */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,5,0)
# define COMPAT_BLOCK_OPEN_PARAMS	struct block_device *bdev, \
					fmode_t mode
# define COMPAT_BLOCK_RELEASE_PARAMS	struct gendisk *disk, \
					fmode_t mode
# define compat_block_open_disk_ref	(bdev->bd_disk)
# define compat_block_open_checkchg_arg	(bdev)
#else
# define COMPAT_BLOCK_OPEN_PARAMS	struct gendisk *disk, \
					blk_mode_t mode
# define COMPAT_BLOCK_RELEASE_PARAMS	struct gendisk *disk
# define compat_block_open_disk_ref	(disk)
# define compat_block_open_checkchg_arg	(disk)
#endif
