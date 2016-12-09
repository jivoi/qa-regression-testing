/*
   Allocate some memory, fill it, and report its location.

   Author: Kees Cook <keescook@chromium.org>
   Copyright 2011 ChromeOS Authors

   make -C /usr/src/linux-headers-$(uname -r) SUBDIRS=$PWD modules
*/

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <asm/io.h>

int *signpost;

static int signpost_virt_show(struct seq_file *m, void *v)
{
    seq_printf(m, "%p\n", signpost);
    return 0;
}

static int signpost_virt_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, signpost_virt_show, NULL);
}

static const struct file_operations signpost_virt_proc_fops = {
        .open           = signpost_virt_proc_open,
        .read           = seq_read,
        .llseek         = seq_lseek,
        .release        = single_release,
};

static int signpost_phys_show(struct seq_file *m, void *v)
{
    seq_printf(m, "%08lx\n", (unsigned long)virt_to_phys(signpost));
    return 0;
}

static int signpost_phys_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, signpost_phys_show, NULL);
}

static const struct file_operations signpost_phys_proc_fops = {
        .open           = signpost_phys_proc_open,
        .read           = seq_read,
        .llseek         = seq_lseek,
        .release        = single_release,
};

static int signpost_value_show(struct seq_file *m, void *v)
{
    seq_printf(m, "%08x\n", *signpost);
    return 0;
}

static int signpost_value_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, signpost_value_show, NULL);
}

static const struct file_operations signpost_value_proc_fops = {
        .open           = signpost_value_proc_open,
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

static int __init signpost_init(void)
{
    struct proc_dir_entry *entry;

    signpost = kmalloc(sizeof(*signpost), GFP_KERNEL);
    if (!signpost) {
	pr_err("kmalloc failed\n");
        goto failed;
    }
    *signpost = 0xfeedface;

    PROC_CREATE(entry, "signpost_virt", S_IRUGO, &signpost_virt_proc_fops);
    if (!entry) {
	pr_err("proc_create virt failed\n");
        goto free_signpost;
    }

    PROC_CREATE(entry, "signpost_phys", S_IRUGO, &signpost_phys_proc_fops);
    if (!entry) {
	pr_err("proc_create phys failed\n");
        goto free_virt;
    }

    PROC_CREATE(entry, "signpost_value", S_IRUGO, &signpost_value_proc_fops);
    if (!entry) {
	pr_err("proc_create value failed\n");
        goto free_phys;
    }

    return 0;

free_phys:
    remove_proc_entry("signpost_phys", NULL);
free_virt:
    remove_proc_entry("signpost_virt", NULL);
free_signpost:
    kfree(signpost);
failed:
    return -ENOMEM;
}

static void __exit signpost_exit(void)
{
    remove_proc_entry("signpost_virt", NULL);
    remove_proc_entry("signpost_phys", NULL);
    remove_proc_entry("signpost_value", NULL);
    kfree(signpost);
}

module_init(signpost_init);
module_exit(signpost_exit);

MODULE_LICENSE("GPL");
