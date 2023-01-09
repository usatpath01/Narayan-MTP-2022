from bcc import BPF
from ctypes import *
program = """
#include <asm/ptrace.h> // for struct pt_regs
#include <linux/types.h> // for mode_t
BPF_PROG_ARRAY(prog_array, 31);

int kprobe__sys_execve(struct pt_regs *ctx,int dirfd,char __user* pathname, int flags, mode_t mode) {
    u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if(uid==0){
        u64 t = bpf_ktime_get_ns();
        bpf_trace_printk("t= %lu\\n",t);
        
        bpf_trace_printk("Before SysCall\\n");
    }
    return 0;
}
int kretprobe__sys_execve(struct pt_regs *ctx,int dirfd,char __user* pathname, int flags, mode_t mode) {
    u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if(uid==0){
        u64 t = bpf_ktime_get_ns();
        bpf_trace_printk("t= %lu\\n",t);

        bpf_trace_printk("After SysCall\\n");
        prog_array.call(ctx, 1);
    }
    return 0;
}

int hello1(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    bpf_trace_printk("This was the last function on the chain\\n");
    return 0;
}
"""

hello=[0]
b = BPF(text=program)
prog_array = b.get_table("prog_array")
for i in range(1,2):
    hello.append( b.load_func("hello%d"%i, BPF.KPROBE))
    prog_array[c_int(i)] = c_int(hello[i].fd)
print("Compiled")
b.trace_print()
