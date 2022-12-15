from bcc import BPF
from time import sleep


program="""
int hello_world(void *ctx){
    u64 t= bpf_ktime_get_ns();
    u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    u64 ptid = bpf_get_current_pid_tgid() ;
    bpf_trace_printk("t= %lu uid: %d pid: %d\\n",t , uid, ptid>>32);
    return 0;
}

"""

b= BPF(text=program)

clone = b.get_syscall_fnname("clone")
b.attach_kprobe(event=clone,fn_name="hello_world")
b.trace_print()
