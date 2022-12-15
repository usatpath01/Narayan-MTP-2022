from bcc import BPF

b= BPF(src_file="concise_tail.c")
clone = b.get_syscall_fnname("clone")
b.attach_kprobe(event=clone,fn_name="hello_world")
b.trace_print()
