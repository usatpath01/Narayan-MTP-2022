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
    prog_array.call(ctx, 2);
    return 0;
}


int hello2(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 3);
    return 0;
}


int hello3(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 4);
    return 0;
}


int hello4(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 5);
    return 0;
}


int hello5(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 6);
    return 0;
}


int hello6(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 7);
    return 0;
}


int hello7(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 8);
    return 0;
}


int hello8(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 9);
    return 0;
}


int hello9(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 10);
    return 0;
}


int hello10(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 11);
    return 0;
}


int hello11(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 12);
    return 0;
}


int hello12(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 13);
    return 0;
}


int hello13(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 14);
    return 0;
}


int hello14(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 15);
    return 0;
}


int hello15(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 16);
    return 0;
}


int hello16(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 17);
    return 0;
}


int hello17(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 18);
    return 0;
}


int hello18(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 19);
    return 0;
}


int hello19(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 20);
    return 0;
}


int hello20(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 21);
    return 0;
}


int hello21(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 22);
    return 0;
}


int hello22(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 23);
    return 0;
}


int hello23(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 24);
    return 0;
}


int hello24(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 25);
    return 0;
}


int hello25(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 26);
    return 0;
}


int hello26(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 27);
    return 0;
}


int hello27(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 28);
    return 0;
}


int hello28(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 29);
    return 0;
}


int hello29(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 30);
    return 0;
}

int hello30(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 31);
    return 0;
}
int hello31(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    prog_array.call(ctx, 32);
    return 0;
}
int hello32(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %lu\\n",t);
    bpf_trace_printk("This was the last function on the chain\\n");
    return 0;
}
"""

hello=[0]
b = BPF(text=program)
prog_array = b.get_table("prog_array")
for i in range(1,33):
    hello.append( b.load_func("hello%d"%i, BPF.KPROBE))
    prog_array[c_int(i)] = c_int(hello[i].fd)
print("Compiled")
b.trace_print()
