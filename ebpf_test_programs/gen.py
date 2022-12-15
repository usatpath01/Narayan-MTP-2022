for i in range(1,30):
    print("""
hello%d = b.load_func("hello%d", BPF.KPROBE)
prog_array[c_int(%d)] = c_int(hello%d.fd)
"""%(i,i,i,i))
