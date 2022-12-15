from bcc import BPF
program = """
#include<uapi/linux/ptrace.h>
#include<linux/sched.h>
#include<linux/fs.h>
int kprobe__sys_execve(struct pt_regs *ctx,char __user *filename){
    char bin[]="/bin";
    #pragma unroll
    for (int i=0;i<4;i++)
    if(bin[i]!=filename[i]){
        bpf_trace_printk("sys_execve outside /bin\\n");
        return 0;
    }
    return 0;
}
"""
b = BPF(text=program)
print("Compiled")
b.trace_print()
