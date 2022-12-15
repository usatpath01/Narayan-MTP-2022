from bcc import BPF
program = """
#include <asm/ptrace.h>
#include <bcc/proto.h>
#include <linux/limits.h>

BPF_PERF_OUTPUT(output); // creates a table for pushing custom events to userspace V

 typedef struct notify {
   uint64_t pid;
   uint8_t data[PATH_MAX];
 } notify_t;
BPF_PERCPU_ARRAY(notify_array, notify_t, 1);

 int kprobe__do_sys_open(struct pt_regs *ctx,
                        int dirfd, char __user* pathname, int flags, mode_t mode){

    int i = 0;
    notify_t* n = notify_array.lookup(&i);
    if (!n) return 0;
    n->pid =(u32) (bpf_get_current_pid_tgid() >> 32);
    bpf_probe_read_str(&n->data[0], PATH_MAX, pathname);
    output.perf_submit(ctx, n, sizeof (notify_t));
    return 0;
}

"""
b = BPF(text=program)
print("Compiled")
b.trace_print()
