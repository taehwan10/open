// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/namei.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * Some corrections by tytso.
 */

/* [Feb 1997 T. Schoebel-Theuer] Complete rewrite of the pathname
 * lookup logic.
 */
/* [Feb-Apr 2000, AV] Rewrite to the new namespace architecture.
 */

#include <linux/init.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/filelock.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/sched/mm.h>
#include <linux/fsnotify.h>
#include <linux/personality.h>
#include <linux/security.h>
#include <linux/ima.h>
#include <linux/syscalls.h>
#include <linux/mount.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <linux/device_cgroup.h>
#include <linux/fs_struct.h>
#include <linux/posix_acl.h>
#include <linux/hash.h>
#include <linux/bitops.h>
#include <linux/init_task.h>
#include <linux/uaccess.h>

#include "internal.h"
#include "mount.h"

#define EMBEDDED_LEVELS 2
struct nameidata {
	struct path	path;
	struct qstr	last;
	struct path	root;
	struct inode	*inode; /* path.dentry.d_inode */
	unsigned int	flags, state;
	unsigned	seq, next_seq, m_seq, r_seq;
	int		last_type;
	unsigned	depth;
	int		total_link_count;
	struct saved {
		struct path link;
		struct delayed_call done;
		const char *name;
		unsigned seq;
	} *stack, internal[EMBEDDED_LEVELS];
	struct filename	*name;
	struct nameidata *saved;
	unsigned	root_seq;
	int		dfd;
	vfsuid_t	dir_vfsuid;
	umode_t		dir_mode;
} __randomize_layout;

#define ND_ROOT_PRESET 1
#define ND_ROOT_GRABBED 2
#define ND_JUMPED 4
//mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm
static void __pxt4_set_nameidata(struct nameidata *p, int dfd, struct filename *name){

	struct nameidata *old = current->nameidata;
	p->stack = p->internal;
	p->depth = 0;
	p->dfd = dfd;
	p->name = name;
	p->path.mnt = NULL;
	p->total_link_count = old ? old->total_link_count : 0;
	p->saved = old;
	current->nameidata = p;
}

static inline void pxt4_set_nameidata(struct nameidata *p, int dfd, struct filename *name,
		const struct path *root){
	__pxt4_set_nameidata(p, dfd, name);
	p->state = 0;
	if(unlikely(root)){
		p->state = ND_ROOT_PRESET;
		p->root = *root;
	}
}
extern int do_tmpfile(struct nameidata *nd, unsigned flags,
		const struct open_flags *op, struct file *file);

extern int do_o_path(struct nameidata *nd, unsigned flags, struct file *file);
extern const char *path_init(struct nameidata *nd, unsigned flags);
int link_path_walk(const char *name, struct nameidata *nd);
const char *open_last_lookups(struct nameidata *nd,
		   struct file *file, const struct open_flags *op);

int do_open(struct nameidata *nd,
		   struct file *file, const struct open_flags *op);

void terminate_walk(struct nameidata *nd);


static struct file *pxt4_path_openat(struct nameidata *nd, const struct open_flags *op, 
		unsigned flags){

	printk("pxt4_path_openat() is start");

	struct file *file;
	int error;

	file = alloc_empty_file(op->open_flag, current_cred());
	if (IS_ERR(file))
		return file;

	if (unlikely(file->f_flags & __O_TMPFILE)){
		error = do_tmpfile(nd, flags, op, file);
	}else if(unlikely(file->f_flags & O_PATH)){
		error = do_o_path(nd, flags, file);
	} else{
		const char *s = path_init(nd, flags);
		while(!(error = link_path_walk(s,nd)) &&
				(s = open_last_lookups(nd, file, op)) != NULL)
			;
		if(!error)
			error = do_open(nd, file, op);
		terminate_walk(nd);
	}
	if(likely(!error)){
		if(likely(file->f_mode & FMODE_OPENED))
			return file;
		WARN_ON(1);
		error = -EINVAL;
	}
	fput(file);
	if (error == -EOPENSTALE) {
		if (flags & LOOKUP_RCU)
			error = -ECHILD;
		else
			error = -ESTALE;
	}
	return ERR_PTR(error);
}

extern void restore_nameidata(void);

struct file *pxt4_do_filp_open(int dfd, struct filename *pathname,
		const struct open_flags *op)
{
	printk("pxt4_do_filp_open is start()");

	struct nameidata nd;
	int flags = op->lookup_flags;
	struct file *filp;

	pxt4_set_nameidata(&nd, dfd, pathname, NULL);
	filp = pxt4_path_openat(&nd, op, flags | LOOKUP_RCU);
	if (unlikely(filp == ERR_PTR(-ECHILD)))
		filp = pxt4_path_openat(&nd, op, flags);
	if (unlikely(filp == ERR_PTR(-ESTALE)))
		filp = pxt4_path_openat(&nd, op, flags | LOOKUP_REVAL);
	restore_nameidata();
	return filp;
}
