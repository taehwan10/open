#include <linux/string.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fsnotify.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/namei.h>
#include <linux/backing-dev.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <linux/security.h>
#include <linux/mount.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/personality.h>
#include <linux/pagemap.h>
#include <linux/syscalls.h>
#include <linux/rcupdate.h>
#include <linux/audit.h>
#include <linux/falloc.h>
#include <linux/fs_struct.h>
#include <linux/ima.h>
#include <linux/dnotify.h>
#include <linux/compat.h>
#include <linux/mnt_idmapping.h>
#include <linux/filelock.h>

//#include "namei.h"
#include "fs/internal.h"
#include "fs/namei.h"

long pxt4_do_sys_openat2(int dfd, const char __user *filename, struct open_how *how){

	printk("pxt4_do_sys_openat2 is start()");
	
	struct open_flags op;
	int fd = build_open_flags(how, &op);
	struct filename *tmp;

	if(fd)
		return fd;

	tmp = getname(filename);
	if(IS_ERR(tmp))
		return PTR_ERR(tmp);

	fd = get_unused_fd_flags(how->flags);
	if(fd >= 0){
		struct file *f = pxt4_do_filp_open(dfd, tmp, &op);
		if(IS_ERR(f)) {
			put_unused_fd(fd);
			fd = PTR_ERR(f);
		} else {
			fd_install(fd,f);
		}
	}
	putname(tmp);
	return fd;
}
EXPORT_SYMBOL(pxt4_do_sys_openat2);

long pxt4_do_sys_open(int dfd, const char __user *filename, int flags, umode_t mode)
{
	printk("pxt4_do_sys_open start()");
	struct open_how how = build_open_how(flags, mode);
	return pxt4_do_sys_openat2(dfd, filename, &how);
}
EXPORT_SYMBOL(pxt4_do_sys_open);

