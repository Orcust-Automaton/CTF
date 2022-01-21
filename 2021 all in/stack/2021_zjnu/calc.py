# -*- encoding: utf-8 -*-
from pwn import * 
context.log_level = "debug"
host = 'hzserver.bi0x.cn'
port = '9872'
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

for i in range(100):
    ru("Please input answer of ")
    rst = eval(p.recvuntil(":")[:-1])
    sl(str(rst))


p.interactive()

'''
@File    :   calc.py
@Time    :   2021/08/17 14:31:51
@Author  :   Niyah 
'''