#usage
#sudo python3 -i main0.py  -b -s execve -n 32
#sudo python3 -b -e -n 16 -s execve
#-b to chain the tail calls at the begining
#-e to chain the tail calls at the end
#-n number of tail calls
#-s name of system call
from bcc import BPF
from ctypes import *
import sys
print(sys.argv)
numcol=2
header="""
#include <asm/ptrace.h> // for struct pt_regs
#include <linux/types.h> // for mode_t
BPF_PROG_ARRAY(prog_array, 35);
BPF_ARRAY(themap, u64, 300);
BPF_ARRAY(fgs, u64, 10);
"""
syscall="execve"
if len(sys.argv)<2:
    begin=True
    end=True
    num=33
else:
    begin=True if ("-b" in sys.argv or "-be" in sys.argv) else False
    end=True if ("-e" in sys.argv or "-be" in sys.argv) else False
    num=32
    for i in range(len(sys.argv)):
        if(sys.argv[i]=="-n"):
            num=int(sys.argv[i+1])
            break
    for i in range(len(sys.argv)):
        if(sys.argv[i]=="-s"):
            syscall=sys.argv[i+1]
            break

#max(num) = 33
hooks="""
int kprobe__sys_%s(struct pt_regs *ctx,int dirfd,char __user* pathname, int flags, mode_t mode) {
    u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if(uid==0){
        u64 t = bpf_ktime_get_ns();
        int z = 0;
        u64 *key = fgs.lookup(&z);
        if(key == NULL ) return 1;
        int k=%d*(*key);
        themap.update(&k,&t);
        t = bpf_ktime_get_ns();
        t = bpf_ktime_get_ns();
        z=299;
        themap.update(&z,&t);
        %s
    }
    return 0;
}
int kretprobe__sys_%s(struct pt_regs *ctx,int dirfd,char __user* pathname, int flags, mode_t mode) {
    u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if(uid==0){
        //fgs.atomic_increment(0);
        int z = 0;
        u64 *key = fgs.lookup(&z);
        if(key == NULL ) return 1;
        u64 zz = *key;
        zz++;
        fgs.update(&z,&zz);
        //u64 t = bpf_ktime_get_ns();
        %s
    }
    return 0;
}
"""%(syscall,numcol,"prog_array.call(ctx, 1);" if begin else "",syscall,"prog_array.call(ctx, 1);" if end else "")

funcs=""

for i in range(1,num):
    funcs+=("""\n\
int hello%d(void *ctx){
    //u64 t = bpf_ktime_get_ns();
    //bpf_trace_printk("hello t= %s\\n",t);
    prog_array.call(ctx, %d);
    return 0;
}
"""%(i,"%lu",i+1))

funcs +="""
int hello%d(void *ctx){
    u64 t = bpf_ktime_get_ns();
    int z = 0;
    u64 *key = fgs.lookup(&z);
    if(key == NULL ) return 1;
    int k=%d*(*key)+1;
    themap.update(&k,&t);
    return 0;
}
"""%(num,numcol)

program=header+hooks+funcs

hello=[0]
b = BPF(text=program)
prog_array = b.get_table("prog_array")
for i in range(1,num+1):
    hello.append( b.load_func("hello%d"%i, BPF.KPROBE))
    prog_array[c_int(i)] = c_int(hello[i].fd)
print("Compiled")
def printvals():
    n=b["fgs"][0].value
    for i in range(n):
        print(b["themap"][2*i].value,",",b["themap"][2*i+1].value)

