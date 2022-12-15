from bcc import BPF
from time import sleep


program="""
BPF_HASH(clones);

int hello_world(void *ctx){
    u64 uid;
    u64 counter =0;
    u64 *p;
    
    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    p = clones.lookup(&uid);
    if(p!=0){
        counter = *p;
    }
    
    counter++;
    clones.update(&uid,&counter);
    return 0;
}

"""

b= BPF(text=program)

clone = b.get_syscall_fnname("clone")
b.attach_kprobe(event=clone,fn_name="hello_world")
z=0
while z<5:
    sleep(1)
    s=""
    z+=1
    if len(b["clones"].items()):
        for k,v in b["clones"].items():
            s+="ID {}: {}\t".format(k.value,v.value)
        print(z,"seconds",s)
    else:
        print("No entries yet")

"""
RUN apt install -y linux-headers-$(uname -r)
"""