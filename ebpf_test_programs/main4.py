from bcc import BPF
program = """
#include <asm/ptrace.h> // for struct pt_regs
#include <linux/types.h> // for mode_t
int kprobe__do_sys_open(struct pt_regs *ctx,int dirfd,char __user* pathname, int flags, mode_t mode) {
    bpf_trace_printk("sys_open called on %s\\n",pathname);
    return 0;
}

}
"""
b = BPF(text=program)
print("Compiled")
b.trace_print()
