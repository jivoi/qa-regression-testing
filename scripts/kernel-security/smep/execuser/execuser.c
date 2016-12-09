/*
   Call back to userspace on read.

   Author: Kees Cook <keescook@chromium.org>
   Copyright 2012 ChromeOS Authors

   make -C /usr/src/linux-headers-$(uname -r) SUBDIRS=$PWD modules
*/

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

static int execuser_show_mapped(struct seq_file *m, void *v)
{
    int (*userspace_function)(void) = (void*)0x10000000;
    if (userspace_function() != 0xfeedbeef)
        return -EFAULT;

    seq_printf(m, "ok\n");
    return 0;
}

static int execuser_open_mapped(struct inode *inode, struct file *file)
{
    return single_open(file, execuser_show_mapped, NULL);
}

static const struct file_operations execuser_fops_mapped = {
    .open           = execuser_open_mapped,
    .read           = seq_read,
    .llseek         = seq_lseek,
    .release        = single_release,
};

static int execuser_show_unmapped(struct seq_file *m, void *v)
{
    int (*userspace_function)(void) = (void*)0x0;
    if (userspace_function() != 0xfeedbeef)
        return -EFAULT;

    seq_printf(m, "ok\n");
    return 0;
}

static int execuser_open_unmapped(struct inode *inode, struct file *file)
{
    return single_open(file, execuser_show_unmapped, NULL);
}

static const struct file_operations execuser_fops_unmapped = {
    .open           = execuser_open_unmapped,
    .read           = seq_read,
    .llseek         = seq_lseek,
    .release        = single_release,
};

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,25)
# define PROC_CREATE(entry, name, mode, func) \
    entry = proc_create(name, mode, NULL, func)
#else
/* older kernel support... */
# define PROC_CREATE(entry, name, mode, func) { \
    entry = create_proc_entry(name, mode, NULL); \
    if (entry) { \
        entry->proc_fops = func; \
        entry->owner = THIS_MODULE; \
    } \
}
#endif

static int __init execuser_init(void)
{
    struct proc_dir_entry *entry;

    PROC_CREATE(entry, "execuser_mapped", S_IRUGO, &execuser_fops_mapped);
    if (!entry) {
        pr_err("proc_create mapped failed\n");
        return -ENOMEM;
    }

    PROC_CREATE(entry, "execuser_unmapped", S_IRUGO, &execuser_fops_unmapped);
    if (!entry) {
        pr_err("proc_create unmapped failed\n");
        remove_proc_entry("execuser_mapped", NULL);
        return -ENOMEM;
    }

    return 0;
}

static void __exit execuser_exit(void)
{
    remove_proc_entry("execuser_mapped", NULL);
    remove_proc_entry("execuser_unmapped", NULL);
}

module_init(execuser_init);
module_exit(execuser_exit);

MODULE_LICENSE("GPL");
