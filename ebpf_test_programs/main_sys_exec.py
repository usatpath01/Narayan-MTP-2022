from bcc import BPF
program = """
#include <asm/ptrace.h> // for struct pt_regs
#include <linux/types.h> // for mode_t
int kprobe__sys_execve(struct pt_regs *ctx,int dirfd,char __user* pathname, int flags, mode_t mode) {
    bpf_trace_printk("sys_execve called.\\n");
    return 0;
}
int kretprobe__sys_execve(struct pt_regs *ctx,int dirfd,char __user* pathname, int flags, mode_t mode) {
    bpf_trace_printk("sys_execve called.\\n");
    return 0;
}
"""
b = BPF(text=program)
print("Compiled")
b.trace_print()
