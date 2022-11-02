package common

const REQ_OP_BITS = 8
const REQ_OP_MASK = ((1 << REQ_OP_BITS) - 1)
const REQ_FLAG_BITS = 24

/* read sectors from the device */
const REQ_OP_READ = 0

/* write sectors to the device */
const REQ_OP_WRITE = 1

/* flush the volatile write cache */
const REQ_OP_FLUSH = 2

/* discard sectors */
const REQ_OP_DISCARD = 3

/* securely erase sectors */
const REQ_OP_SECURE_ERASE = 5

/* reset a zone write pointer */
const REQ_OP_ZONE_RESET = 6

/* write the same sector many times */
const REQ_OP_WRITE_SAME = 7

/* reset all the zone present on the device */
const REQ_OP_ZONE_RESET_ALL = 8

/* write the zero filled sector many times */
const REQ_OP_WRITE_ZEROES = 9

/* Open a zone */
const REQ_OP_ZONE_OPEN = 10

/* Close a zone */
const REQ_OP_ZONE_CLOSE = 11

/* Transition a zone to full */
const REQ_OP_ZONE_FINISH = 12

/* SCSI passthrough using struct scsi_request */
const REQ_OP_SCSI_IN = 32
const REQ_OP_SCSI_OUT = 33

/* Driver private requests */
const REQ_OP_DRV_IN = 34
const REQ_OP_DRV_OUT = 35

const REQ_OP_LAST = 36

const (
	__REQ_FAILFAST_DEV = iota + REQ_OP_BITS /* no driver retries of device errors */

	__REQ_FAILFAST_TRANSPORT /* no driver retries of transport errors */
	__REQ_FAILFAST_DRIVER    /* no driver retries of driver errors */
	__REQ_SYNC               /* request is sync (sync write or read) */
	__REQ_META               /* metadata io request */
	__REQ_PRIO               /* boost priority in cfq */
	__REQ_NOMERGE            /* don't touch this for merging */
	__REQ_IDLE               /* anticipate more IO after this one */
	__REQ_INTEGRITY          /* I/O includes block integrity payload */
	__REQ_FUA                /* forced unit access */
	__REQ_PREFLUSH           /* request for cache flush */
	__REQ_RAHEAD             /* read ahead, can fail anytime */
	__REQ_BACKGROUND         /* background IO */
	__REQ_NOWAIT             /* Don't wait if request will block */
	__REQ_NOWAIT_INLINE      /* Return would-block error inline */
	/*
	 * When a shared kthread needs to issue a bio for a cgroup, doing
	 * so synchronously can lead to priority inversions as the kthread
	 * can be trapped waiting for that cgroup.  CGROUP_PUNT flag makes
	 * submit_bio() punt the actual issuing to a dedicated per-blkcg
	 * work item to avoid such priority inversions.
	 */
	__REQ_CGROUP_PUNT

	/* command specific flags for REQ_OP_WRITE_ZEROES: */
	__REQ_NOUNMAP /* do not free blocks when zeroing */

	__REQ_HIPRI

	/* for driver use */
	__REQ_DRV
	__REQ_SWAP    /* swapping request. */
	__REQ_NR_BITS /* stops here */
)

const REQ_FAILFAST_DEV = 1 << __REQ_FAILFAST_DEV
const REQ_FAILFAST_TRANSPORT = 1 << __REQ_FAILFAST_TRANSPORT
const REQ_FAILFAST_DRIVER = 1 << __REQ_FAILFAST_DRIVER
const REQ_SYNC = 1 << __REQ_SYNC
const REQ_META = 1 << __REQ_META
const REQ_PRIO = 1 << __REQ_PRIO
const REQ_NOMERGE = 1 << __REQ_NOMERGE
const REQ_IDLE = 1 << __REQ_IDLE
const REQ_INTEGRITY = 1 << __REQ_INTEGRITY
const REQ_FUA = 1 << __REQ_FUA
const REQ_PREFLUSH = 1 << __REQ_PREFLUSH
const REQ_RAHEAD = 1 << __REQ_RAHEAD
const REQ_BACKGROUND = 1 << __REQ_BACKGROUND
const REQ_NOWAIT = 1 << __REQ_NOWAIT
const REQ_NOWAIT_INLINE = 1 << __REQ_NOWAIT_INLINE
const REQ_CGROUP_PUNT = 1 << __REQ_CGROUP_PUNT

const REQ_NOUNMAP = 1 << __REQ_NOUNMAP
const REQ_HIPRI = 1 << __REQ_HIPRI

const REQ_DRV = 1 << __REQ_DRV
const REQ_SWAP = 1 << __REQ_SWAP

const REQ_FAILFAST_MASK = REQ_FAILFAST_DEV | REQ_FAILFAST_TRANSPORT | REQ_FAILFAST_DRIVER

const REQ_NOMERGE_FLAGS = REQ_NOMERGE | REQ_PREFLUSH | REQ_FUA
