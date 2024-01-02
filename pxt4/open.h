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

struct file *pxt4_do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op);
inline struct open_how build_open_how(int flags, umode_t mode);

//extern long do_sys_openat2(int dfd, const char __user *filename, struct open_how *how);

long pxt4_do_sys_openat2(int dfd, const char __user *filename, struct open_how *how);

long pxt4_do_sys_open(int dfd, const char __user *filename, int flags, umode_t mode);

