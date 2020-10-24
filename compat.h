/*
 * Declarations to provide compatibility with all kernel versions from
 * 2.6.36 up, without littering the code with #ifdefs all over.
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

/* (*make_request_fn)() return type was changed in 3.2 and 4.4 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
# define COMPAT_REQUEST_RETTYPE		int
# define COMPAT_REQUEST_RETURN()	return(0)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
# define COMPAT_REQUEST_RETTYPE		void
# define COMPAT_REQUEST_RETURN()	return
#else
# define COMPAT_REQUEST_RETTYPE		blk_qc_t
# define COMPAT_REQUEST_RETURN()	return(BLK_QC_T_NONE)
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)
# define compat_backing_dev_info_ptr(request_queue)  (&(request_queue->backing_dev_info))
#else
# define compat_backing_dev_info_ptr(request_queue)  request_queue->backing_dev_info
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
#define compat_request_get_queue()	(bio->bi_disk->queue)
/* (Notice the trailing comma) */
#define COMPAT_SET_SUBMIT_BIO(fn)	.submit_bio = (fn),

#endif
