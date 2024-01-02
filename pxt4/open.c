#include "open.h"

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

