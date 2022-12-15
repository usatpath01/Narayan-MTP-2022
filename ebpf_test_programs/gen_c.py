for i in range(1,30):
    print("""\n\
int hello%d(void *ctx){
    u64 t = bpf_ktime_get_ns();
    bpf_trace_printk("t= %s\\\\n",t);
    prog_array.call(ctx, %d);
    return 0;
}
"""%(i,"%lu",i+1))


