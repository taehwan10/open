// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/random.h>
#include <linux/buffer_head.h>
#include <linux/utsname.h>
#include <linux/kthread.h>

#include "pxt4.h"

/* Checksumming functions */
static __le32 pxt4_mmp_csum(struct super_block *sb, struct mmp_struct *mmp)
{
	struct pxt4_sb_info *sbi = PXT4_SB(sb);
	int offset = offsetof(struct mmp_struct, mmp_checksum);
	__u32 csum;

	csum = pxt4_chksum(sbi, sbi->s_csum_seed, (char *)mmp, offset);

	return cpu_to_le32(csum);
}

static int pxt4_mmp_csum_verify(struct super_block *sb, struct mmp_struct *mmp)
{
	if (!pxt4_has_metadata_csum(sb))
		return 1;

	return mmp->mmp_checksum == pxt4_mmp_csum(sb, mmp);
}

static void pxt4_mmp_csum_set(struct super_block *sb, struct mmp_struct *mmp)
{
	if (!pxt4_has_metadata_csum(sb))
		return;

	mmp->mmp_checksum = pxt4_mmp_csum(sb, mmp);
}

/*
 * Write the MMP block using REQ_SYNC to try to get the block on-disk
 * faster.
 */
static int write_mmp_block_thawed(struct super_block *sb,
				  struct buffer_head *bh)
{
	struct mmp_struct *mmp = (struct mmp_struct *)(bh->b_data);

	pxt4_mmp_csum_set(sb, mmp);
	lock_buffer(bh);
	bh->b_end_io = end_buffer_write_sync;
	get_bh(bh);
	submit_bh(REQ_OP_WRITE | REQ_SYNC | REQ_META | REQ_PRIO, bh);
	wait_on_buffer(bh);
	if (unlikely(!buffer_uptodate(bh)))
		return -EIO;
	return 0;
}

static int write_mmp_block(struct super_block *sb, struct buffer_head *bh)
{
	int err;

	/*
	 * We protect against freezing so that we don't create dirty buffers
	 * on frozen filesystem.
	 */
	sb_start_write(sb);
	err = write_mmp_block_thawed(sb, bh);
	sb_end_write(sb);
	return err;
}

/*
 * Read the MMP block. It _must_ be read from disk and hence we clear the
 * uptodate flag on the buffer.
 */
static int read_mmp_block(struct super_block *sb, struct buffer_head **bh,
			  pxt4_fsblk_t mmp_block)
{
	struct mmp_struct *mmp;
	int ret;

	if (*bh)
		clear_buffer_uptodate(*bh);

	/* This would be sb_bread(sb, mmp_block), except we need to be sure
	 * that the MD RAID device cache has been bypassed, and that the read
	 * is not blocked in the elevator. */
	if (!*bh) {
		*bh = sb_getblk(sb, mmp_block);
		if (!*bh) {
			ret = -ENOMEM;
			goto warn_exit;
		}
	}

	lock_buffer(*bh);
	ret = pxt4_read_bh(*bh, REQ_META | REQ_PRIO, NULL);
	if (ret)
		goto warn_exit;

	mmp = (struct mmp_struct *)((*bh)->b_data);
	if (le32_to_cpu(mmp->mmp_magic) != PXT4_MMP_MAGIC) {
		ret = -EFSCORRUPTED;
		goto warn_exit;
	}
	if (!pxt4_mmp_csum_verify(sb, mmp)) {
		ret = -EFSBADCRC;
		goto warn_exit;
	}
	return 0;
warn_exit:
	brelse(*bh);
	*bh = NULL;
	pxt4_warning(sb, "Error %d while reading MMP block %llu",
		     ret, mmp_block);
	return ret;
}

/*
 * Dump as much information as possible to help the admin.
 */
void __dump_mmp_msg(struct super_block *sb, struct mmp_struct *mmp,
		    const char *function, unsigned int line, const char *msg)
{
	__pxt4_warning(sb, function, line, "%s", msg);
	__pxt4_warning(sb, function, line,
		       "MMP failure info: last update time: %llu, last update node: %.*s, last update device: %.*s",
		       (unsigned long long)le64_to_cpu(mmp->mmp_time),
		       (int)sizeof(mmp->mmp_nodename), mmp->mmp_nodename,
		       (int)sizeof(mmp->mmp_bdevname), mmp->mmp_bdevname);
}

/*
 * kmmpd will update the MMP sequence every s_mmp_update_interval seconds
 */
static int kmmpd(void *data)
{
	struct super_block *sb = data;
	struct pxt4_super_block *es = PXT4_SB(sb)->s_es;
	struct buffer_head *bh = PXT4_SB(sb)->s_mmp_bh;
	struct mmp_struct *mmp;
	pxt4_fsblk_t mmp_block;
	u32 seq = 0;
	unsigned long failed_writes = 0;
	int mmp_update_interval = le16_to_cpu(es->s_mmp_update_interval);
	unsigned mmp_check_interval;
	unsigned long last_update_time;
	unsigned long diff;
	int retval = 0;

	mmp_block = le64_to_cpu(es->s_mmp_block);
	mmp = (struct mmp_struct *)(bh->b_data);
	mmp->mmp_time = cpu_to_le64(ktime_get_real_seconds());
	/*
	 * Start with the higher mmp_check_interval and reduce it if
	 * the MMP block is being updated on time.
	 */
	mmp_check_interval = max(PXT4_MMP_CHECK_MULT * mmp_update_interval,
				 PXT4_MMP_MIN_CHECK_INTERVAL);
	mmp->mmp_check_interval = cpu_to_le16(mmp_check_interval);

	memcpy(mmp->mmp_nodename, init_utsname()->nodename,
	       sizeof(mmp->mmp_nodename));

	while (!kthread_should_stop() && !pxt4_forced_shutdown(sb)) {
		if (!pxt4_has_feature_mmp(sb)) {
			pxt4_warning(sb, "kmmpd being stopped since MMP feature"
				     " has been disabled.");
			goto wait_to_exit;
		}
		if (++seq > PXT4_MMP_SEQ_MAX)
			seq = 1;

		mmp->mmp_seq = cpu_to_le32(seq);
		mmp->mmp_time = cpu_to_le64(ktime_get_real_seconds());
		last_update_time = jiffies;

		retval = write_mmp_block(sb, bh);
		/*
		 * Don't spew too many error messages. Print one every
		 * (s_mmp_update_interval * 60) seconds.
		 */
		if (retval) {
			if ((failed_writes % 60) == 0) {
				pxt4_error_err(sb, -retval,
					       "Error writing to MMP block");
			}
			failed_writes++;
		}

		diff = jiffies - last_update_time;
		if (diff < mmp_update_interval * HZ)
			schedule_timeout_interruptible(mmp_update_interval *
						       HZ - diff);

		/*
		 * We need to make sure that more than mmp_check_interval
		 * seconds have not passed since writing. If that has happened
		 * we need to check if the MMP block is as we left it.
		 */
		diff = jiffies - last_update_time;
		if (diff > mmp_check_interval * HZ) {
			struct buffer_head *bh_check = NULL;
			struct mmp_struct *mmp_check;

			retval = read_mmp_block(sb, &bh_check, mmp_block);
			if (retval) {
				pxt4_error_err(sb, -retval,
					       "error reading MMP data: %d",
					       retval);
				goto wait_to_exit;
			}

			mmp_check = (struct mmp_struct *)(bh_check->b_data);
			if (mmp->mmp_seq != mmp_check->mmp_seq ||
			    memcmp(mmp->mmp_nodename, mmp_check->mmp_nodename,
				   sizeof(mmp->mmp_nodename))) {
				dump_mmp_msg(sb, mmp_check,
					     "Error while updating MMP info. "
					     "The filesystem seems to have been"
					     " multiply mounted.");
				pxt4_error_err(sb, EBUSY, "abort");
				put_bh(bh_check);
				retval = -EBUSY;
				goto wait_to_exit;
			}
			put_bh(bh_check);
		}

		 /*
		 * Adjust the mmp_check_interval depending on how much time
		 * it took for the MMP block to be written.
		 */
		mmp_check_interval = max(min(PXT4_MMP_CHECK_MULT * diff / HZ,
					     PXT4_MMP_MAX_CHECK_INTERVAL),
					 PXT4_MMP_MIN_CHECK_INTERVAL);
		mmp->mmp_check_interval = cpu_to_le16(mmp_check_interval);
	}

	/*
	 * Unmount seems to be clean.
	 */
	mmp->mmp_seq = cpu_to_le32(PXT4_MMP_SEQ_CLEAN);
	mmp->mmp_time = cpu_to_le64(ktime_get_real_seconds());

	retval = write_mmp_block(sb, bh);

wait_to_exit:
	while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (!kthread_should_stop())
			schedule();
	}
	set_current_state(TASK_RUNNING);
	return retval;
}

void pxt4_stop_mmpd(struct pxt4_sb_info *sbi)
{
	if (sbi->s_mmp_tsk) {
		kthread_stop(sbi->s_mmp_tsk);
		brelse(sbi->s_mmp_bh);
		sbi->s_mmp_tsk = NULL;
	}
}

/*
 * Get a random new sequence number but make sure it is not greater than
 * PXT4_MMP_SEQ_MAX.
 */
static unsigned int mmp_new_seq(void)
{
	return get_random_u32_below(PXT4_MMP_SEQ_MAX + 1);
}

/*
 * Protect the filesystem from being mounted more than once.
 */
int pxt4_multi_mount_protect(struct super_block *sb,
				    pxt4_fsblk_t mmp_block)
{
	struct pxt4_super_block *es = PXT4_SB(sb)->s_es;
	struct buffer_head *bh = NULL;
	struct mmp_struct *mmp = NULL;
	u32 seq;
	unsigned int mmp_check_interval = le16_to_cpu(es->s_mmp_update_interval);
	unsigned int wait_time = 0;
	int retval;

	if (mmp_block < le32_to_cpu(es->s_first_data_block) ||
	    mmp_block >= pxt4_blocks_count(es)) {
		pxt4_warning(sb, "Invalid MMP block in superblock");
		retval = -EINVAL;
		goto failed;
	}

	retval = read_mmp_block(sb, &bh, mmp_block);
	if (retval)
		goto failed;

	mmp = (struct mmp_struct *)(bh->b_data);

	if (mmp_check_interval < PXT4_MMP_MIN_CHECK_INTERVAL)
		mmp_check_interval = PXT4_MMP_MIN_CHECK_INTERVAL;

	/*
	 * If check_interval in MMP block is larger, use that instead of
	 * update_interval from the superblock.
	 */
	if (le16_to_cpu(mmp->mmp_check_interval) > mmp_check_interval)
		mmp_check_interval = le16_to_cpu(mmp->mmp_check_interval);

	seq = le32_to_cpu(mmp->mmp_seq);
	if (seq == PXT4_MMP_SEQ_CLEAN)
		goto skip;

	if (seq == PXT4_MMP_SEQ_FSCK) {
		dump_mmp_msg(sb, mmp, "fsck is running on the filesystem");
		retval = -EBUSY;
		goto failed;
	}

	wait_time = min(mmp_check_interval * 2 + 1,
			mmp_check_interval + 60);

	/* Print MMP interval if more than 20 secs. */
	if (wait_time > PXT4_MMP_MIN_CHECK_INTERVAL * 4)
		pxt4_warning(sb, "MMP interval %u higher than expected, please"
			     " wait.\n", wait_time * 2);

	if (schedule_timeout_interruptible(HZ * wait_time) != 0) {
		pxt4_warning(sb, "MMP startup interrupted, failing mount\n");
		retval = -ETIMEDOUT;
		goto failed;
	}

	retval = read_mmp_block(sb, &bh, mmp_block);
	if (retval)
		goto failed;
	mmp = (struct mmp_struct *)(bh->b_data);
	if (seq != le32_to_cpu(mmp->mmp_seq)) {
		dump_mmp_msg(sb, mmp,
			     "Device is already active on another node.");
		retval = -EBUSY;
		goto failed;
	}

skip:
	/*
	 * write a new random sequence number.
	 */
	seq = mmp_new_seq();
	mmp->mmp_seq = cpu_to_le32(seq);

	/*
	 * On mount / remount we are protected against fs freezing (by s_umount
	 * semaphore) and grabbing freeze protection upsets lockdep
	 */
	retval = write_mmp_block_thawed(sb, bh);
	if (retval)
		goto failed;

	/*
	 * wait for MMP interval and check mmp_seq.
	 */
	if (schedule_timeout_interruptible(HZ * wait_time) != 0) {
		pxt4_warning(sb, "MMP startup interrupted, failing mount");
		retval = -ETIMEDOUT;
		goto failed;
	}

	retval = read_mmp_block(sb, &bh, mmp_block);
	if (retval)
		goto failed;
	mmp = (struct mmp_struct *)(bh->b_data);
	if (seq != le32_to_cpu(mmp->mmp_seq)) {
		dump_mmp_msg(sb, mmp,
			     "Device is already active on another node.");
		retval = -EBUSY;
		goto failed;
	}

	PXT4_SB(sb)->s_mmp_bh = bh;

	BUILD_BUG_ON(sizeof(mmp->mmp_bdevname) < BDEVNAME_SIZE);
	snprintf(mmp->mmp_bdevname, sizeof(mmp->mmp_bdevname),
		 "%pg", bh->b_bdev);

	/*
	 * Start a kernel thread to update the MMP block periodically.
	 */
	PXT4_SB(sb)->s_mmp_tsk = kthread_run(kmmpd, sb, "kmmpd-%.*s",
					     (int)sizeof(mmp->mmp_bdevname),
					     mmp->mmp_bdevname);
	if (IS_ERR(PXT4_SB(sb)->s_mmp_tsk)) {
		PXT4_SB(sb)->s_mmp_tsk = NULL;
		pxt4_warning(sb, "Unable to create kmmpd thread for %s.",
			     sb->s_id);
		retval = -ENOMEM;
		goto failed;
	}

	return 0;

failed:
	brelse(bh);
	return retval;
}
