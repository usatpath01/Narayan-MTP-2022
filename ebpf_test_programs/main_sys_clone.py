from bcc import BPF
program = """
#include <asm/ptrace.h> // for struct pt_regs
#include <linux/types.h> // for mode_t
int kprobe__sys_clone(struct pt_regs *ctx,int dirfd,char __user* pathname, int flags, mode_t mode) {
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("sys_clone called %lu \\n",t);
    return 0;
}
int kretprobe__sys_clone(struct pt_regs *ctx,int dirfd,char __user* pathname, int flags, mode_t mode) {
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("sys_clone called %lu \\n\\n",t);
    return 0;
}
"""
b = BPF(text=program)
print("Compiled")
b.trace_print()
